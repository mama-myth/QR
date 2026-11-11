import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'kb_models.dart';

/// A cryptographically signed knowledge base delta update package.
class SignedKnowledgeBaseDelta {
  final int deltaVersion;
  final List<KnowledgeBaseEntry> entries;
  final List<String> revokedEntityIds;
  final DateTime timestamp;
  final String signerKeyId;
  final String signature; // HMAC-SHA256 signature of canonical payload

  const SignedKnowledgeBaseDelta({
    required this.deltaVersion,
    required this.entries,
    required this.revokedEntityIds,
    required this.timestamp,
    required this.signerKeyId,
    required this.signature,
  });

  /// Generates the canonical serialized string representation used for signing and verification.
  String get canonicalDigestString {
    final entryHashes = entries.map((e) => '${e.entityId}:${e.patternHash}:${e.versionId}').join(',');
    final revokes = revokedEntityIds.join(',');
    return '$deltaVersion|$entryHashes|$revokes|${timestamp.toIso8601String()}|$signerKeyId';
  }
}

/// Verifier enforcing signature pinning, monotonic versioning, and anti-rollback.
class KnowledgeBaseDeltaVerifier {
  // Pinned trusted root signing keys
  static const Map<String, String> _pinnedKeys = {
    'root_ca_sec_2026': 'd07a9354024f8d951859d0739b81cf78696ec065d64817454868019e34a65ec0',
  };

  /// Computes expected HMAC-SHA256 signature for a delta using a given key.
  static String computeSignature(String canonicalData, String secretKey) {
    final hmac = Hmac(sha256, utf8.encode(secretKey));
    return hmac.convert(utf8.encode(canonicalData)).toString();
  }

  /// Verifies delta validity against current version and pinned root keys.
  static bool verify({
    required SignedKnowledgeBaseDelta delta,
    required int currentVersion,
  }) {
    // 1. Anti-rollback: deltaVersion must be strictly greater than currentVersion
    if (delta.deltaVersion <= currentVersion) {
      return false;
    }

    // 2. Reject expired or future-skewed deltas (> 7 days old or > 1 hour in future)
    final now = DateTime.now().toUtc();
    if (delta.timestamp.isAfter(now.add(const Duration(hours: 1)))) {
      return false;
    }
    if (delta.timestamp.isBefore(now.subtract(const Duration(days: 7)))) {
      return false;
    }

    // 3. Pinned signing key validation
    final pinnedSecret = _pinnedKeys[delta.signerKeyId];
    if (pinnedSecret == null) {
      return false; // Unknown or untrusted signer key
    }

    // 4. Verify cryptographic signature
    final expectedSignature = computeSignature(delta.canonicalDigestString, pinnedSecret);
    return expectedSignature == delta.signature;
  }
}
