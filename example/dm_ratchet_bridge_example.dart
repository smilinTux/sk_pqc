// Example: hybrid KEM + the 1:1 DM epoch-ratchet bridge (Alice <-> Bob).
//
// Shows the Level-3 running ratchet: a per-conversation epoch secret distributed
// ONCE per epoch over the hybrid KEM (x25519-mlkem768), then many per-message
// keys derived symmetrically + index-addressably from it. Periodic rekey starts
// a fresh independent epoch — forward secrecy across the boundary,
// post-compromise security within. The ~1.1 KB of ML-KEM ciphertext is paid once
// per epoch, NOT per message.
//
// The derived secret is confidential if EITHER X25519 OR ML-KEM-768 holds —
// "hybrid", not "quantum-proof".
//
// Run on native (Linux/macOS/Windows) with liboqs available:
//   LD_LIBRARY_PATH=$HOME/.local/lib \
//   SK_PQC_LIBOQS=$HOME/.local/lib/liboqs.so \
//   dart run example/dm_ratchet_bridge_example.dart

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:sk_pqc/sk_pqc.dart';

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

final _aes = AesGcm.with256bits();

/// Alice: take the next outbound key, AES-256-GCM seal, return what goes on the
/// wire: (index, nonce, ciphertext+tag).
Future<(int, Uint8List, SecretBox)> send(
  DmRatchet ratchet,
  List<int> plaintext,
) async {
  final (index, key) = await ratchet.nextOutboundKey();
  final box = await _aes.encrypt(plaintext, secretKey: SecretKey(key));
  return (index, Uint8List.fromList(box.nonce), box);
}

/// Bob: derive the key for the CARRIED index (loss/reorder tolerant), open.
Future<List<int>> receive(DmRatchet ratchet, int index, SecretBox box) async {
  final key = await ratchet.messageKey(index: index);
  return _aes.decrypt(box, secretKey: SecretKey(key));
}

Future<void> main() async {
  final kem = HybridKemImpl();
  print('suite: ${kem.suiteId}');
  print('ml-kem backend: ${kem.mlkemImplName}');

  // --- Part 1: the raw hybrid KEM (what the ratchet is built on) -------------
  final recipient = await kem.generateKeyPair();
  final enc = await kem.encapsulate(recipient.publicKey);
  final recovered = await kem.decapsulate(enc.ciphertext, recipient.privateKey);
  print('hybrid KEM shared secrets match: '
      '${hex(recovered) == hex(enc.sharedSecret)}');

  // --- Part 2: the DM epoch-ratchet bridge -----------------------------------
  // Bob publishes a long-term hybrid prekey.
  final bob = await kem.generateKeyPair();

  // Epoch 0: Alice mints an epoch secret and wraps it to Bob's hybrid key ONCE.
  final e0 = newEpochSecret();
  final payload = await wrapDmEpochSecret(e0, bob.publicKey, kem: kem);
  print('epoch-0 wrap payload: ${payload.length} bytes '
      '(hybrid ct + nonce + sealed)');

  final bobE0 = await unwrapDmEpochSecret(payload, bob.privateKey, kem: kem);
  assert(hex(bobE0) == hex(e0)); // both sides hold the same epoch secret

  final alice = DmRatchet(epoch: 0, epochSecret: e0);
  final bobR = DmRatchet(epoch: 0, epochSecret: bobE0);

  // Several messages keyed off the one epoch secret — no per-message PQ cost.
  for (final text in ['hi bob', "how's the sovereign net?", 'pq ratchet works']) {
    final (idx, _, box) = await send(alice, text.codeUnits);
    final got = await receive(bobR, idx, box);
    print('  msg[$idx] -> "${String.fromCharCodes(got)}"');
    assert(String.fromCharCodes(got) == text);
  }

  // Out-of-order delivery: index-addressable keys make reorder fine.
  final (i0, _, b0) = await send(alice, 'first'.codeUnits);
  final (i1, _, b1) = await send(alice, 'second'.codeUnits);
  assert(String.fromCharCodes(await receive(bobR, i1, b1)) == 'second');
  assert(String.fromCharCodes(await receive(bobR, i0, b0)) == 'first');
  print('  out-of-order delivery: OK (index-addressable)');

  // Epoch 1: periodic rekey — forward secrecy + post-compromise security.
  final e1 = newEpochSecret();
  assert(hex(e1) != hex(e0)); // independent — a leaked e0 reveals only epoch 0
  final bobE1 = await unwrapDmEpochSecret(
      await wrapDmEpochSecret(e1, bob.publicKey, kem: kem),
      bob.privateKey,
      kem: kem);
  final alice1 = DmRatchet(epoch: 1, epochSecret: e1);
  final bob1 = DmRatchet(epoch: 1, epochSecret: bobE1);
  final (idx, _, box) = await send(alice1, 'healed channel'.codeUnits);
  assert(String.fromCharCodes(await receive(bob1, idx, box)) == 'healed channel');

  final oldKey = await alice.messageKey(index: 0);
  final newKey = await alice1.messageKey(index: 0);
  assert(hex(oldKey) != hex(newKey)); // PCS: prior epoch key is dead
  print('  rekey to epoch 1: OK (prior epoch key is dead — PCS)');

  print('\nOK — hybrid KEM + DM ratchet bridge roundtrip succeeded.');
}
