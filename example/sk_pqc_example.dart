// Example: hybrid post-quantum key encapsulation (X25519 + ML-KEM-768).
//
// Run on native (Linux/macOS/Windows) with liboqs available:
//   LD_LIBRARY_PATH=$HOME/.local/lib \
//   SK_PQC_LIBOQS=$HOME/.local/lib/liboqs.so \
//   dart run example/sk_pqc_example.dart
//
// On web, bundle web/sk_pqc_noble_bootstrap.js first (see README).

import 'dart:typed_data';

import 'package:sk_pqc/sk_pqc.dart';

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Future<void> main() async {
  // One API, backend chosen automatically (liboqs native / noble web).
  final kem = HybridKemImpl();
  print('suite: ${kem.suiteId}');
  print('ml-kem backend: ${kem.mlkemImplName}');

  // Recipient generates a long-term hybrid keypair and publishes the public key.
  final recipient = await kem.generateKeyPair();
  print('public key:  ${recipient.publicKey.length} bytes '
      '(x25519 32 + ml-kem-768 1184)');
  print('private key: ${recipient.privateKey.length} bytes');

  // Sender encapsulates to the recipient's public key.
  final enc = await kem.encapsulate(recipient.publicKey);
  print('ciphertext:  ${enc.ciphertext.length} bytes '
      '(x25519 eph 32 + ml-kem-768 ct 1088)');
  print('sender secret:    ${hex(enc.sharedSecret)}');

  // Recipient decapsulates and recovers the SAME shared secret.
  final recovered = await kem.decapsulate(enc.ciphertext, recipient.privateKey);
  print('recipient secret: ${hex(recovered)}');

  final match = hex(recovered) == hex(enc.sharedSecret);
  print('shared secrets match: $match');

  // Use the 32-byte shared secret as an AES-256-GCM / ChaCha20 key, or feed it
  // into a further KDF for per-message keys. The secret is quantum-resistant as
  // long as EITHER X25519 or ML-KEM-768 remains unbroken.
}
