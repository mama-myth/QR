import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/fusion/evaluation_result.dart';
import 'package:peek_in_qr/core/fusion/fusion_engine.dart';
import 'package:peek_in_qr/core/kb/kb_models.dart';
import 'package:peek_in_qr/core/kb/kb_repository.dart';
import 'package:peek_in_qr/core/payload/payload_parser.dart';

void main() {
  late KnowledgeBaseRepository kbRepo;
  late FusionEngine fusionEngine;

  setUp(() {
    kbRepo = KnowledgeBaseRepository(
      initialEntries: [
        KnowledgeBaseEntry(
          entityId: 'gov_portal_01',
          canonicalPattern: 'portal.gov.example',
          category: 'GOVERNMENT',
          trustAssertion: TrustAssertion.verifiedSafe,
          signatureProvenance: 'root_ca_sec_2026',
          versionId: 10,
          expiresAt: DateTime.now().toUtc().add(const Duration(days: 365)),
        ),
        KnowledgeBaseEntry(
          entityId: 'phish_known_01',
          canonicalPattern: 'known-phish.attacker.invalid',
          category: 'MALICIOUS_FEED',
          trustAssertion: TrustAssertion.knownMalicious,
          signatureProvenance: 'threat_intel_feed_01',
          versionId: 10,
          expiresAt: DateTime.now().toUtc().add(const Duration(days: 30)),
        ),
        KnowledgeBaseEntry(
          entityId: 'expired_entry',
          canonicalPattern: 'expired-trust.example',
          category: 'MERCHANT',
          trustAssertion: TrustAssertion.verifiedSafe,
          signatureProvenance: 'old_ca',
          versionId: 2,
          expiresAt: DateTime.now().toUtc().subtract(const Duration(days: 1)),
        ),
      ],
    );

    fusionEngine = FusionEngine(kbRepository: kbRepo);
  });

  group('Evidence Fusion Invariants', () {
    test(
      'clean benign target without positive proof MUST evaluate to UNKNOWN',
      () {
        final payload = PayloadParser.parse(
          'https://regular-unregistered-site.com/about',
        );
        final result = fusionEngine.evaluate(payload);

        expect(result.state, EvaluationState.unknown);
        expect(result.reasonCodes.contains('NO_POSITIVE_PROOF'), isTrue);
      },
    );

    test(
      'target with positive, authenticated, fresh trust proof evaluates to VERIFIED',
      () {
        final payload = PayloadParser.parse(
          'https://portal.gov.example/services',
        );
        final result = fusionEngine.evaluate(payload);

        expect(result.state, EvaluationState.verified);
        expect(
          result.reasonCodes.contains('KB_POSITIVE_TRUST_VERIFIED'),
          isTrue,
        );
      },
    );

    test('target with expired trust proof defaults to UNKNOWN', () {
      final payload = PayloadParser.parse('https://expired-trust.example/pay');
      final result = fusionEngine.evaluate(payload);

      expect(result.state, EvaluationState.unknown);
      expect(result.reasonCodes.contains('NO_POSITIVE_PROOF'), isTrue);
    });

    test(
      'target matching known malicious KB entry evaluates to SUSPICIOUS',
      () {
        final payload = PayloadParser.parse(
          'https://known-phish.attacker.invalid/login',
        );
        final result = fusionEngine.evaluate(payload);

        expect(result.state, EvaluationState.suspicious);
        expect(result.reasonCodes.contains('KB_KNOWN_MALICIOUS'), isTrue);
      },
    );

    test(
      'target with critical malicious rule (IP host) evaluates to SUSPICIOUS regardless of absence in KB',
      () {
        final payload = PayloadParser.parse('http://192.168.1.100/admin');
        final result = fusionEngine.evaluate(payload);

        expect(result.state, EvaluationState.suspicious);
        expect(result.reasonCodes.contains('RULE_URL_IP_HOST'), isTrue);
      },
    );

    test(
      'target with positive trust proof but conflicting warning evaluates to UNKNOWN (contradiction check)',
      () {
        // portal.gov.example with duplicate parameter pollution
        final payload = PayloadParser.parse(
          'https://portal.gov.example/login?token=abc&token=xyz',
        );
        final result = fusionEngine.evaluate(payload);

        // Must NOT be verified due to contradictory duplicate parameter warning
        expect(result.state, EvaluationState.unknown);
        expect(
          result.reasonCodes.contains('RULE_URL_DUPLICATE_PARAMS'),
          isTrue,
        );
      },
    );

    test(
      'missing KB component records degradation flag and defaults to UNKNOWN without crashing',
      () {
        final degradedEngine = const FusionEngine(kbRepository: null);
        final payload = PayloadParser.parse('https://portal.gov.example/test');
        final result = degradedEngine.evaluate(payload);

        expect(result.degradationFlags['kbAvailable'], isFalse);
        expect(result.state, EvaluationState.unknown);
      },
    );
  });

  group('Knowledge Base and Scan History Repository', () {
    test(
      'records scan history with redacted summary and allows full deletion',
      () {
        final record = ScanRecord(
          scanId: 'scan-uuid-1234',
          timestamp: DateTime.now().toUtc(),
          payloadType: 'URL',
          evaluationState: 'UNKNOWN',
          reasonCodes: ['NO_POSITIVE_PROOF'],
          consentAction: 'BLOCKED',
          redactedSummary: 'https://example.com/***',
        );

        kbRepo.recordScan(record);
        expect(kbRepo.getScanHistory().length, 1);
        expect(
          kbRepo.getScanHistory().first.redactedSummary,
          'https://example.com/***',
        );

        kbRepo.clearHistory();
        expect(kbRepo.getScanHistory(), isEmpty);
      },
    );
  });
}
