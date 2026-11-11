import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/kb/kb_models.dart';
import 'package:peek_in_qr/core/kb/kb_repository.dart';
import 'package:peek_in_qr/core/kb/kb_sync.dart';

void main() {
  const rootKeyId = 'root_ca_sec_2026';
  const rootKeySecret = 'd07a9354024f8d951859d0739b81cf78696ec065d64817454868019e34a65ec0';

  late KnowledgeBaseRepository repo;

  setUp(() {
    repo = KnowledgeBaseRepository(
      initialVersion: 5,
      initialEntries: [
        KnowledgeBaseEntry(
          entityId: 'entry_initial_1',
          canonicalPattern: 'trusted.org',
          category: 'MERCHANT',
          trustAssertion: TrustAssertion.verifiedSafe,
          signatureProvenance: 'root_ca_sec_2026',
          versionId: 5,
          expiresAt: DateTime.now().toUtc().add(const Duration(days: 30)),
        ),
      ],
    );
  });

  group('Gate G7: Signed KB Deltas and Synchronization Invariants', () {
    test('successfully applies a valid signed delta and advances version', () {
      final newEntry = KnowledgeBaseEntry(
        entityId: 'entry_new_portal',
        canonicalPattern: 'newportal.gov.example',
        category: 'GOVERNMENT',
        trustAssertion: TrustAssertion.verifiedSafe,
        signatureProvenance: 'root_ca_sec_2026',
        versionId: 6,
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 90)),
      );

      final deltaWithoutSig = SignedKnowledgeBaseDelta(
        deltaVersion: 6,
        entries: [newEntry],
        revokedEntityIds: [],
        timestamp: DateTime.now().toUtc(),
        signerKeyId: rootKeyId,
        signature: '',
      );

      final validSig = KnowledgeBaseDeltaVerifier.computeSignature(
        deltaWithoutSig.canonicalDigestString,
        rootKeySecret,
      );

      final signedDelta = SignedKnowledgeBaseDelta(
        deltaVersion: 6,
        entries: [newEntry],
        revokedEntityIds: [],
        timestamp: deltaWithoutSig.timestamp,
        signerKeyId: rootKeyId,
        signature: validSig,
      );

      final res = repo.applySignedDelta(signedDelta);
      expect(res.success, isTrue);
      expect(res.status, 'APPLIED');
      expect(repo.currentVersion, 6);

      // Verify the new entry is now discoverable
      final lookupRes = repo.lookup('newportal.gov.example');
      expect(lookupRes, isNotNull);
      expect(lookupRes!.entityId, 'entry_new_portal');
    });

    test('strictly rejects tampered cryptographic signature and retains last known good state', () {
      final newEntry = KnowledgeBaseEntry(
        entityId: 'entry_hacked',
        canonicalPattern: 'hacker-site.attacker.invalid',
        category: 'GOVERNMENT',
        trustAssertion: TrustAssertion.verifiedSafe,
        signatureProvenance: 'root_ca_sec_2026',
        versionId: 7,
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 90)),
      );

      final tamperedDelta = SignedKnowledgeBaseDelta(
        deltaVersion: 7,
        entries: [newEntry],
        revokedEntityIds: [],
        timestamp: DateTime.now().toUtc(),
        signerKeyId: rootKeyId,
        signature: 'invalid_forged_signature_000000000000000000000000000000',
      );

      final res = repo.applySignedDelta(tamperedDelta);
      expect(res.success, isFalse);
      expect(res.status, 'REJECTED_SIGNATURE');
      expect(repo.currentVersion, 5); // Unchanged

      // Verify hacked entry was not applied
      expect(repo.lookup('hacker-site.attacker.invalid'), isNull);
    });

    test('strictly rejects rollback attempt (deltaVersion <= currentVersion)', () {
      final rollbackEntry = KnowledgeBaseEntry(
        entityId: 'stale_entry',
        canonicalPattern: 'stale.example',
        category: 'MERCHANT',
        trustAssertion: TrustAssertion.verifiedSafe,
        signatureProvenance: 'root_ca_sec_2026',
        versionId: 4,
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 30)),
      );

      final rollbackDelta = SignedKnowledgeBaseDelta(
        deltaVersion: 4, // Current is 5
        entries: [rollbackEntry],
        revokedEntityIds: [],
        timestamp: DateTime.now().toUtc(),
        signerKeyId: rootKeyId,
        signature: 'sig',
      );

      final res = repo.applySignedDelta(rollbackDelta);
      expect(res.success, isFalse);
      expect(res.status, 'REJECTED_ROLLBACK');
      expect(repo.currentVersion, 5);
    });

    test('rejects unsigned or unpinned signer keys', () {
      final entry = KnowledgeBaseEntry(
        entityId: 'untrusted_key_entry',
        canonicalPattern: 'untrusted.example',
        category: 'BANKING',
        trustAssertion: TrustAssertion.verifiedSafe,
        signatureProvenance: 'unknown_key_999',
        versionId: 10,
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 30)),
      );

      final unpinnedDelta = SignedKnowledgeBaseDelta(
        deltaVersion: 10,
        entries: [entry],
        revokedEntityIds: [],
        timestamp: DateTime.now().toUtc(),
        signerKeyId: 'unpinned_rogue_ca',
        signature: 'dummy_sig',
      );

      final res = repo.applySignedDelta(unpinnedDelta);
      expect(res.success, isFalse);
      expect(res.status, 'REJECTED_SIGNATURE');
    });

    test('performs atomic rollback when entry validation fails during commit', () {
      final invalidEntry = KnowledgeBaseEntry(
        entityId: '', // Invalid empty entityId
        canonicalPattern: '',
        category: 'MERCHANT',
        trustAssertion: TrustAssertion.verifiedSafe,
        signatureProvenance: 'root_ca_sec_2026',
        versionId: 8,
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 30)),
      );

      final deltaWithoutSig = SignedKnowledgeBaseDelta(
        deltaVersion: 8,
        entries: [invalidEntry],
        revokedEntityIds: [],
        timestamp: DateTime.now().toUtc(),
        signerKeyId: rootKeyId,
        signature: '',
      );

      final validSig = KnowledgeBaseDeltaVerifier.computeSignature(
        deltaWithoutSig.canonicalDigestString,
        rootKeySecret,
      );

      final delta = SignedKnowledgeBaseDelta(
        deltaVersion: 8,
        entries: [invalidEntry],
        revokedEntityIds: [],
        timestamp: deltaWithoutSig.timestamp,
        signerKeyId: rootKeyId,
        signature: validSig,
      );

      final res = repo.applySignedDelta(delta);
      expect(res.success, isFalse);
      expect(res.status, 'VALIDATION_FAILED');
      expect(repo.currentVersion, 5); // Rolled back
    });
  });
}
