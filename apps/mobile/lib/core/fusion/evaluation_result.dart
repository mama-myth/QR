import '../rules/rule_evidence.dart';

/// The authoritative tri-state evaluation verdict.
enum EvaluationState { verified, unknown, suspicious }

/// The aggregated evaluation result produced by the Evidence Fusion Engine.
///
/// Invariants:
/// - `VERIFIED` requires explicit, positive, authenticated, fresh trust proof
///   and NO contradictory evidence.
/// - Any strong high-confidence malicious rule -> `SUSPICIOUS`.
/// - Ambiguous, unproven, missing component, or conflicting evidence -> `UNKNOWN`.
/// - A failed, stale, or missing network/KB/ML component CANNOT increase assurance.
class EvaluationResult {
  final EvaluationState state;
  final List<String> reasonCodes;
  final List<String> userMessages;
  final List<RuleEvidence> evidenceList;
  final bool evaluatedOnline;
  final Map<String, bool> degradationFlags;
  final String policyVersion;

  const EvaluationResult({
    required this.state,
    required this.reasonCodes,
    required this.userMessages,
    required this.evidenceList,
    this.evaluatedOnline = false,
    this.degradationFlags = const {},
    this.policyVersion = '1.0.0',
  });

  Map<String, dynamic> toJson() => {
    'state': state.name.toUpperCase(),
    'reasonCodes': reasonCodes,
    'userMessages': userMessages,
    'evaluatedOnline': evaluatedOnline,
    'degradationFlags': degradationFlags,
    'policyVersion': policyVersion,
    'evidence': evidenceList.map((e) => e.toJson()).toList(),
  };
}
