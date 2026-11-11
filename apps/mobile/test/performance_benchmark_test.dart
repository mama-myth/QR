import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/fusion/fusion_engine.dart';
import 'package:peek_in_qr/core/kb/kb_models.dart';
import 'package:peek_in_qr/core/kb/kb_repository.dart';
import 'package:peek_in_qr/core/payload/payload_parser.dart';
import 'package:peek_in_qr/core/payload/qr_payload.dart';
import 'package:peek_in_qr/core/kb/report_generator.dart';
import 'fixtures/adversarial_fixtures.dart';

void main() {
  late KnowledgeBaseRepository kbRepo;
  late FusionEngine fusionEngine;

  setUp(() {
    kbRepo = KnowledgeBaseRepository(initialEntries: [
      KnowledgeBaseEntry(
        entityId: 'gov_portal_01',
        canonicalPattern: 'portal.gov.example',
        category: 'GOVERNMENT',
        trustAssertion: TrustAssertion.verifiedSafe,
        signatureProvenance: 'root_ca_sec_2026',
        versionId: 10,
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 365)),
      ),
    ]);
    fusionEngine = FusionEngine(kbRepository: kbRepo);
  });

  group('Gate G8: Performance Benchmarks & Report Generator', () {
    test('measures local decision path latency against <100ms target', () {
      final samplePayloads = [
        AdversarialFixtures.benignUrl,
        AdversarialFixtures.ipHostUrl,
        AdversarialFixtures.confusablePunycodeUrl,
        AdversarialFixtures.benignUpi,
        AdversarialFixtures.escapedWifi,
        AdversarialFixtures.benignPhone,
        AdversarialFixtures.promptInjectionText,
      ];

      final latenciesMs = <double>[];

      // Warm-up run
      for (final raw in samplePayloads) {
        final parsed = PayloadParser.parse(raw);
        fusionEngine.evaluate(parsed);
      }

      // Measurement run: 100 iterations
      const iterations = 100;
      for (var i = 0; i < iterations; i++) {
        final raw = samplePayloads[i % samplePayloads.length];
        final stopwatch = Stopwatch()..start();

        final parsed = PayloadParser.parse(raw);
        fusionEngine.evaluate(parsed);

        stopwatch.stop();
        latenciesMs.add(stopwatch.elapsedMicroseconds / 1000.0);
      }

      latenciesMs.sort();
      final p50 = latenciesMs[(latenciesMs.length * 0.50).toInt()];
      final p95 = latenciesMs[(latenciesMs.length * 0.95).toInt()];
      final maxLatency = latenciesMs.last;

      // Verify that local evaluation path is significantly below the 100ms target
      expect(p50, lessThan(100.0));
      expect(p95, lessThan(100.0));
      expect(maxLatency, lessThan(100.0));
    });

    test('generates redacted diagnostic audit report without leaking sensitive secrets', () {
      final qrPayload = QRPayload(
        entrypoint: 'tile',
        rawContent: 'WIFI:S:SecretCorpOffice;T:WPA;P:SuperSecretP@ssword123;;',
      );
      final parsed = PayloadParser.parse(qrPayload.rawContent);
      final evaluation = fusionEngine.evaluate(parsed);

      final report = DiagnosticReportGenerator.generateReport(
        qrPayload: qrPayload,
        parsedPayload: parsed,
        evaluation: evaluation,
        consentAction: 'BLOCKED',
      );

      expect(report['reportVersion'], '1.0.0');
      expect(report['scanMetadata']['entrypoint'], 'tile');
      expect(report['scanMetadata']['payloadType'], 'WIFI');
      expect(report['actionAudit']['consentAction'], 'BLOCKED');

      // Verify password is NOT in diagnosticProperties
      final diagProps = report['targetSummary']['diagnosticProperties'] as Map<String, dynamic>;
      expect(diagProps.containsKey('password'), isFalse);
      expect(diagProps['hasPassword'], isTrue);
    });
  });
}
