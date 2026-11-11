import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/reputation/reputation_client.dart';

void main() {
  group('SafeReputationClient Invariants', () {
    test('defaults to UNAVAILABLE when network transport is unconfigured', () async {
      final client = SafeReputationClient();
      final res = await client.checkReputation('example.com');

      expect(res.status, 'UNAVAILABLE');
      expect(res.message.contains('disabled or transport unconfigured'), isTrue);
    });

    test('hashes identifier and parses malicious response safely', () async {
      String? sentBody;
      Future<String?> mockTransport(String body) async {
        sentBody = body;
        return '{"status": "VERIFIED_MALICIOUS", "token_prefix": "e3b0c442", "reputation_score": 0.95, "cached": false, "message": "Threat detected"}';
      }

      final client = SafeReputationClient(networkTransport: mockTransport);
      final res = await client.checkReputation('malicious-site.attacker.invalid');

      expect(sentBody, isNotNull);
      expect(sentBody!.contains('lookup_token'), isTrue);
      // Ensure raw domain name is NOT leaked in the body
      expect(sentBody!.contains('malicious-site.attacker.invalid'), isFalse);
      expect(res.status, 'VERIFIED_MALICIOUS');
      expect(res.isMalicious, isTrue);
      expect(res.reputationScore, 0.95);
    });

    test('network transport timeout falls back to UNAVAILABLE safely', () async {
      Future<String?> timeoutTransport(String body) async {
        return null; // Simulates timeout
      }

      final client = SafeReputationClient(networkTransport: timeoutTransport);
      final res = await client.checkReputation('timeout.example.com');

      expect(res.status, 'UNAVAILABLE');
      expect(res.message.contains('timeout or unreachable'), isTrue);
    });
  });
}
