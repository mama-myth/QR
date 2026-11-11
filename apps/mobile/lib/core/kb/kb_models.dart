import 'dart:convert';
import 'package:crypto/crypto.dart';

/// Trust assertion level stored in the Knowledge Base.
enum TrustAssertion { verifiedSafe, knownMalicious, neutral }

/// An entry in the signed/versioned local Knowledge Base.
///
/// Invariants:
/// - Trust is NOT inferred from mere presence; only explicit `verifiedSafe`
///   with valid non-expired signature constitutes positive proof.
/// - Authenticated updates require valid signing key and monotonic version.
class KnowledgeBaseEntry {
  final String entityId;
  final String canonicalPattern;
  final String patternHash; // SHA-256 of canonical pattern
  final String
  category; // 'BANKING', 'GOVERNMENT', 'MERCHANT', 'MALICIOUS_FEED', etc.
  final TrustAssertion trustAssertion;
  final String signatureProvenance; // e.g. 'root_ca_2026'
  final int versionId;
  final DateTime expiresAt;

  KnowledgeBaseEntry({
    required this.entityId,
    required this.canonicalPattern,
    String? patternHash,
    required this.category,
    required this.trustAssertion,
    required this.signatureProvenance,
    required this.versionId,
    required this.expiresAt,
  }) : patternHash = patternHash ?? _computeHash(canonicalPattern);

  static String _computeHash(String input) {
    return sha256.convert(utf8.encode(input.trim().toLowerCase())).toString();
  }

  bool get isExpired => DateTime.now().toUtc().isAfter(expiresAt);

  bool get isPositiveTrustProof =>
      trustAssertion == TrustAssertion.verifiedSafe &&
      !isExpired &&
      signatureProvenance.isNotEmpty;

  Map<String, dynamic> toJson() => {
    'entityId': entityId,
    'canonicalPattern': canonicalPattern,
    'patternHash': patternHash,
    'category': category,
    'trustAssertion': trustAssertion.name,
    'signatureProvenance': signatureProvenance,
    'versionId': versionId,
    'expiresAt': expiresAt.toIso8601String(),
  };
}

/// Redacted scan record saved in local scan history.
///
/// Invariants:
/// - Never stores raw QR payloads, full query strings, or Wi-Fi passwords by default.
/// - Redacted target summary is suitable for export and audit.
class ScanRecord {
  final String scanId;
  final DateTime timestamp;
  final String payloadType;
  final String evaluationState; // 'VERIFIED', 'UNKNOWN', 'SUSPICIOUS'
  final List<String> reasonCodes;
  final String consentAction; // 'PENDING', 'APPROVED', 'CANCELLED', 'BLOCKED'
  final String redactedSummary;

  const ScanRecord({
    required this.scanId,
    required this.timestamp,
    required this.payloadType,
    required this.evaluationState,
    required this.reasonCodes,
    required this.consentAction,
    required this.redactedSummary,
  });

  Map<String, dynamic> toJson() => {
    'scanId': scanId,
    'timestamp': timestamp.toIso8601String(),
    'payloadType': payloadType,
    'evaluationState': evaluationState,
    'reasonCodes': reasonCodes,
    'consentAction': consentAction,
    'redactedSummary': redactedSummary,
  };
}
