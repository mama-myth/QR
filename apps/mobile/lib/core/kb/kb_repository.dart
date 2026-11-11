import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'kb_models.dart';
import 'kb_sync.dart';

/// Outcome of applying a signed delta update.
class DeltaApplyResult {
  final bool success;
  final String
  status; // 'APPLIED', 'REJECTED_SIGNATURE', 'REJECTED_ROLLBACK', 'VALIDATION_FAILED'
  final String message;
  final int version;

  const DeltaApplyResult({
    required this.success,
    required this.status,
    required this.message,
    required this.version,
  });
}

/// Local Knowledge Base and Scan History Repository.
///
/// Implements deterministic lookups, version tracking, history redaction,
/// signed delta synchronization with atomic apply and safe rollback.
class KnowledgeBaseRepository {
  final Map<String, KnowledgeBaseEntry> _entriesByHash = {};
  final List<ScanRecord> _scanHistory = [];
  int _currentVersion = 1;

  KnowledgeBaseRepository({
    List<KnowledgeBaseEntry>? initialEntries,
    int initialVersion = 1,
  }) : _currentVersion = initialVersion {
    if (initialEntries != null) {
      for (final entry in initialEntries) {
        addEntry(entry);
      }
    }
  }

  int get currentVersion => _currentVersion;

  void addEntry(KnowledgeBaseEntry entry) {
    _entriesByHash[entry.patternHash] = entry;
    if (entry.versionId > _currentVersion) {
      _currentVersion = entry.versionId;
    }
  }

  /// Lookup a target identifier (e.g. domain name, UPI payee handle).
  KnowledgeBaseEntry? lookup(String identifier) {
    final hash = sha256
        .convert(utf8.encode(identifier.trim().toLowerCase()))
        .toString();
    final entry = _entriesByHash[hash];
    if (entry != null && !entry.isExpired) {
      return entry;
    }
    return null;
  }

  /// Atomically applies a cryptographically signed knowledge base delta update.
  ///
  /// Invariants:
  /// - Fails closed: if signature, timestamp, or any entry is invalid, rolls back completely.
  /// - Anti-rollback: deltaVersion must be strictly > currentVersion.
  /// - Preserves last-known-good state upon transaction failure.
  DeltaApplyResult applySignedDelta(SignedKnowledgeBaseDelta delta) {
    // 1. Verify cryptographic signature and version bounds
    final isValidSignature = KnowledgeBaseDeltaVerifier.verify(
      delta: delta,
      currentVersion: _currentVersion,
    );

    if (!isValidSignature) {
      if (delta.deltaVersion <= _currentVersion) {
        return DeltaApplyResult(
          success: false,
          status: 'REJECTED_ROLLBACK',
          message:
              'Delta version (${delta.deltaVersion}) is <= current version ($_currentVersion). Anti-rollback triggered.',
          version: _currentVersion,
        );
      }
      return DeltaApplyResult(
        success: false,
        status: 'REJECTED_SIGNATURE',
        message:
            'Delta cryptographic signature or pinned key verification failed.',
        version: _currentVersion,
      );
    }

    // 2. Prepare transaction staging copy for atomic application
    final stagedEntries = Map<String, KnowledgeBaseEntry>.from(_entriesByHash);

    try {
      // Process revocations
      for (final revokeId in delta.revokedEntityIds) {
        stagedEntries.removeWhere((_, entry) => entry.entityId == revokeId);
      }

      // Process new and updated entries with integrity validation
      for (final entry in delta.entries) {
        if (entry.entityId.isEmpty || entry.canonicalPattern.isEmpty) {
          throw const FormatException(
            'Invalid entry: missing entityId or pattern',
          );
        }
        stagedEntries[entry.patternHash] = entry;
      }

      // 3. Commit transaction atomically
      _entriesByHash.clear();
      _entriesByHash.addAll(stagedEntries);
      _currentVersion = delta.deltaVersion;

      return DeltaApplyResult(
        success: true,
        status: 'APPLIED',
        message: 'Signed knowledge base delta applied successfully.',
        version: _currentVersion,
      );
    } catch (e) {
      // Rollback: staged changes discarded, repository remains untouched
      return DeltaApplyResult(
        success: false,
        status: 'VALIDATION_FAILED',
        message:
            'Atomic transaction aborted: $e. Rolled back to last-known-good state.',
        version: _currentVersion,
      );
    }
  }

  /// Record a scan into history.
  void recordScan(ScanRecord record) {
    _scanHistory.add(record);
  }

  /// Retrieve full scan history.
  List<ScanRecord> getScanHistory() {
    return List.unmodifiable(_scanHistory);
  }

  /// Clears all local scan history.
  void clearHistory() {
    _scanHistory.clear();
  }

  int get entryCount => _entriesByHash.length;
}
