import '../kb/kb_models.dart';
import '../kb/kb_repository.dart';
import '../payload/parsed_payload.dart';
import '../ml/model_adapter.dart';
import '../rules/rule_engine.dart';
import '../rules/rule_evidence.dart';
import 'evaluation_result.dart';

/// Authoritative Evidence Fusion Engine implementing the non-negotiable
/// tri-state security policy.
class FusionEngine {
  static const String policyVersion = '1.0.0';

  final KnowledgeBaseRepository? kbRepository;
  final MlModelAdapter? mlAdapter;

  const FusionEngine({
    this.kbRepository,
    this.mlAdapter,
  });

  /// Evaluates a parsed payload deterministically across rule engine, KB, and ML adapter.
  EvaluationResult evaluate(ParsedPayload payload, {bool isNetworkAvailable = false}) {
    final degradationFlags = <String, bool>{
      'kbAvailable': kbRepository != null,
      'mlAvailable': mlAdapter != null && mlAdapter!.isModelLoaded,
      'networkAvailable': isNetworkAvailable,
    };

    final evidence = RuleEngine.evaluate(payload);
    final reasonCodes = <String>[];
    final userMessages = <String>[];

    // Check for Critical Malicious Evidence
    final criticalMatches = evidence
        .where((e) => e.severity == RuleSeverity.critical && e.outcome == RuleOutcome.matched)
        .toList();

    for (final e in criticalMatches) {
      reasonCodes.add(e.ruleId);
      userMessages.add(e.reasonMessage);
    }

    // Check for Knowledge Base match
    KnowledgeBaseEntry? kbEntry;
    if (kbRepository != null) {
      String? lookupTarget;
      if (payload is UrlPayload) {
        lookupTarget = payload.host;
      } else if (payload is UpiPayload) {
        lookupTarget = payload.payeeVpa;
      }

      if (lookupTarget != null && lookupTarget.isNotEmpty) {
        kbEntry = kbRepository!.lookup(lookupTarget);
      }
    }

    // 1. If KB lists the entity as known malicious, treat as SUSPICIOUS
    if (kbEntry != null && kbEntry.trustAssertion == TrustAssertion.knownMalicious) {
      reasonCodes.add('KB_KNOWN_MALICIOUS');
      userMessages.add('Target is cataloged as known malicious in the local Knowledge Base.');
      return EvaluationResult(
        state: EvaluationState.suspicious,
        reasonCodes: reasonCodes,
        userMessages: userMessages,
        evidenceList: evidence,
        evaluatedOnline: isNetworkAvailable,
        degradationFlags: degradationFlags,
        policyVersion: policyVersion,
      );
    }

    // 2. Strong high-confidence malicious rule -> SUSPICIOUS
    if (criticalMatches.isNotEmpty) {
      return EvaluationResult(
        state: EvaluationState.suspicious,
        reasonCodes: reasonCodes,
        userMessages: userMessages,
        evidenceList: evidence,
        evaluatedOnline: isNetworkAvailable,
        degradationFlags: degradationFlags,
        policyVersion: policyVersion,
      );
    }

    // 3. Positive Trust Proof Check for VERIFIED
    // Mandate: VERIFIED strictly requires positive, authenticated, fresh trust proof AND no warnings/contradictions.
    final warningMatches = evidence
        .where((e) => e.severity == RuleSeverity.warning && e.outcome == RuleOutcome.matched)
        .toList();

    for (final e in warningMatches) {
      reasonCodes.add(e.ruleId);
      userMessages.add(e.reasonMessage);
    }

    final hasPositiveProof = kbEntry != null && kbEntry.isPositiveTrustProof;

    if (hasPositiveProof && warningMatches.isEmpty && !payload.isMalformed) {
      reasonCodes.add('KB_POSITIVE_TRUST_VERIFIED');
      userMessages.add('Target identity is cryptographically authenticated and registered in the Knowledge Base (${kbEntry.category}).');
      return EvaluationResult(
        state: EvaluationState.verified,
        reasonCodes: reasonCodes,
        userMessages: userMessages,
        evidenceList: evidence,
        evaluatedOnline: isNetworkAvailable,
        degradationFlags: degradationFlags,
        policyVersion: policyVersion,
      );
    }

    // 4. Fallback / Default: UNKNOWN
    // Clean rules alone or lack of positive proof MUST result in UNKNOWN.
    if (warningMatches.isNotEmpty) {
      userMessages.insert(0, 'Target contains potential risk factors or anomalies.');
    } else {
      reasonCodes.add('NO_POSITIVE_PROOF');
      userMessages.add('Target is not registered in the verified Knowledge Base. Proceed with caution.');
    }

    return EvaluationResult(
      state: EvaluationState.unknown,
      reasonCodes: reasonCodes,
      userMessages: userMessages,
      evidenceList: evidence,
      evaluatedOnline: isNetworkAvailable,
      degradationFlags: degradationFlags,
      policyVersion: policyVersion,
    );
  }
}
