import 'dart:convert';
import 'package:crypto/crypto.dart';

/// Threat reputation lookup response received from the backend service.
class ReputationLookupResult {
  final String status; // 'VERIFIED_MALICIOUS', 'CLEAN', 'UNAVAILABLE', 'UNKNOWN'
  final String tokenPrefix;
  final double? reputationScore;
  final bool cached;
  final String message;

  const ReputationLookupResult({
    required this.status,
    required this.tokenPrefix,
    this.reputationScore,
    this.cached = false,
    required this.message,
  });

  bool get isMalicious => status == 'VERIFIED_MALICIOUS';
}

/// Abstract contract for reputation lookup client.
abstract class ReputationClient {
  Future<ReputationLookupResult> checkReputation(String canonicalIdentifier);
}

/// Safe client for privacy-preserving reputation enrichment.
///
/// Invariants:
/// - Never transmits raw URLs, queries, payment accounts, or Wi-Fi passwords.
/// - Only transmits a SHA-256 hash or hash prefix of the identifier.
/// - Backend timeout or unavailability safely defaults to `UNAVAILABLE`
///   without affecting offline deterministic evaluation.
class SafeReputationClient implements ReputationClient {
  final Future<String?> Function(String jsonBody)? networkTransport;

  SafeReputationClient({this.networkTransport});

  @override
  Future<ReputationLookupResult> checkReputation(String canonicalIdentifier) async {
    // 1. Hash the identifier (e.g. domain name)
    final hashToken = sha256.convert(utf8.encode(canonicalIdentifier.trim().toLowerCase())).toString();

    // 2. Transmit only hash token, never raw payload or query string
    final requestBody = jsonEncode({
      'lookup_token': hashToken,
      'protocol_version': '1.0.0',
    });

    try {
      if (networkTransport == null) {
        return const ReputationLookupResult(
          status: 'UNAVAILABLE',
          tokenPrefix: '',
          message: 'Network reputation service disabled or transport unconfigured. Offline path active.',
        );
      }

      final responseText = await networkTransport!(requestBody);
      if (responseText == null) {
        return const ReputationLookupResult(
          status: 'UNAVAILABLE',
          tokenPrefix: '',
          message: 'Network reputation timeout or unreachable.',
        );
      }

      final data = jsonDecode(responseText) as Map<String, dynamic>;
      return ReputationLookupResult(
        status: data['status'] as String? ?? 'UNAVAILABLE',
        tokenPrefix: data['token_prefix'] as String? ?? '',
        reputationScore: (data['reputation_score'] as num?)?.toDouble(),
        cached: data['cached'] as bool? ?? false,
        message: data['message'] as String? ?? '',
      );
    } catch (e) {
      return ReputationLookupResult(
        status: 'UNAVAILABLE',
        tokenPrefix: hashToken.substring(0, 16),
        message: 'Network lookup failed ($e). Preserving safe offline behavior.',
      );
    }
  }
}
