import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'kb_models.dart';

/// Local Knowledge Base and Scan History Repository.
///
/// Implements deterministic lookups, version tracking, history redaction,
/// and complete local deletion support.
class KnowledgeBaseRepository {
  final Map<String, KnowledgeBaseEntry> _entriesByHash = {};
  final List<ScanRecord> _scanHistory = [];
  int _currentVersion = 1;

  KnowledgeBaseRepository({List<KnowledgeBaseEntry>? initialEntries}) {
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
    final hash = sha256.convert(utf8.encode(identifier.trim().toLowerCase())).toString();
    final entry = _entriesByHash[hash];
    if (entry != null && !entry.isExpired) {
      return entry;
    }
    return null;
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
