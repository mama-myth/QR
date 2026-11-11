import 'dart:math';

/// Immutable model representing an unanalyzed, inert QR payload.
///
/// Invariant:
/// Capturing a QR payload DOES NOT trigger any navigation, intent dispatch,
/// network request, payment, or dialing action. The payload is inert.
class QRPayload {
  final String scanId;
  final String entrypoint; // 'app_icon', 'tile', 'test_fixture', etc.
  final String rawContent; // Transient memory representation
  final DateTime timestamp;

  QRPayload({
    String? scanId,
    required this.entrypoint,
    required this.rawContent,
    DateTime? timestamp,
  }) : scanId = scanId ?? _generateUuid(),
       timestamp = timestamp ?? DateTime.now().toUtc();

  static String _generateUuid() {
    final random = Random();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // UUID version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // UUID variant
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Returns a preview representation with length bounding to avoid UI overflow.
  String get maskedPreview {
    if (rawContent.isEmpty) return '<empty payload>';
    if (rawContent.length <= 60) return rawContent;
    return '${rawContent.substring(0, 30)}...${rawContent.substring(rawContent.length - 25)}';
  }
}
