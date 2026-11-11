/// Severity levels for emitted rule evidence.
enum RuleSeverity { critical, warning, info }

/// Evaluation outcome for an individual deterministic rule.
enum RuleOutcome { matched, notMatched, inconclusive, error }

/// Immutable evidence item produced by a deterministic security rule.
///
/// Invariants:
/// - Absence of findings DOES NOT equate to VERIFIED.
/// - Outcomes distinguish matched, not_matched, inconclusive, and error.
class RuleEvidence {
  final String ruleId;
  final String ruleVersion;
  final String source;
  final RuleSeverity severity;
  final RuleOutcome outcome;
  final String reasonMessage;
  final Map<String, dynamic> redactedDetails;

  const RuleEvidence({
    required this.ruleId,
    this.ruleVersion = '1.0.0',
    this.source = 'deterministic_rules',
    required this.severity,
    required this.outcome,
    required this.reasonMessage,
    this.redactedDetails = const {},
  });

  Map<String, dynamic> toJson() => {
    'ruleId': ruleId,
    'ruleVersion': ruleVersion,
    'source': source,
    'severity': severity.name,
    'outcome': outcome.name,
    'reasonMessage': reasonMessage,
    'redactedDetails': redactedDetails,
  };
}
