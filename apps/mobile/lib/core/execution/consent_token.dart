/// Supported types of external destination actions.
enum DestinationActionType {
  viewUrl,
  initiatePayment,
  dialPhone,
  displayWifi,
  copyText,
}

/// Immutable consent token bound to a specific scan and action.
///
/// Invariants:
/// - Tied to immutable `scanId`, canonical target, and action type.
/// - Valid only for a bounded window (default 60 seconds) to prevent TOCTOU.
/// - Once executed or cancelled, cannot be replayed or reused.
class ConsentToken {
  final String tokenId;
  final String scanId;
  final DestinationActionType actionType;
  final String canonicalTarget;
  final DateTime createdAt;
  final Duration validityDuration;
  bool isUsed;

  ConsentToken({
    required this.tokenId,
    required this.scanId,
    required this.actionType,
    required this.canonicalTarget,
    DateTime? createdAt,
    this.validityDuration = const Duration(seconds: 60),
    this.isUsed = false,
  }) : createdAt = createdAt ?? DateTime.now().toUtc();

  bool get isExpired =>
      DateTime.now().toUtc().isAfter(createdAt.add(validityDuration));

  bool get isValid => !isUsed && !isExpired;
}
