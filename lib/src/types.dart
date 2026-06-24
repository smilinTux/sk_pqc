import 'dart:typed_data';

/// A hybrid KEM keypair.
///
/// Both [publicKey] and [privateKey] are the byte CONCATENATION of the
/// X25519 part followed by the ML-KEM-768 part. See [SkPqcSizes] and the
/// README "Wire format" section for the exact layout — this is part of the
/// cross-implementation interop contract.
class HybridKeyPair {
  /// Concatenation: `X25519_pub (32) ‖ MLKEM768_pub (1184)` = 1216 bytes.
  final Uint8List publicKey;

  /// Concatenation: `X25519_priv (32) ‖ MLKEM768_secret (2400)` = 2432 bytes.
  final Uint8List privateKey;

  const HybridKeyPair({required this.publicKey, required this.privateKey});
}

/// The result of [HybridKem.encapsulate].
class EncapResult {
  /// Concatenation: `X25519_ephemeral_pub (32) ‖ MLKEM768_ciphertext (1088)`
  /// = 1120 bytes. Send this to the peer; they decapsulate it with their
  /// private key.
  final Uint8List ciphertext;

  /// The 32-byte hybrid shared secret = `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)`.
  /// This is identical to what the peer recovers via [HybridKem.decapsulate].
  final Uint8List sharedSecret;

  const EncapResult({required this.ciphertext, required this.sharedSecret});
}

/// Fixed byte sizes for the `x25519-mlkem768` suite. These are part of the
/// interop contract and MUST NOT change.
class SkPqcSizes {
  SkPqcSizes._();

  // X25519 (RFC 7748).
  static const int x25519PublicKey = 32;
  static const int x25519PrivateKey = 32;
  static const int x25519Ciphertext = 32; // ephemeral public key
  static const int x25519SharedSecret = 32;

  // ML-KEM-768 (FIPS 203).
  static const int mlkem768PublicKey = 1184;
  static const int mlkem768SecretKey = 2400;
  static const int mlkem768Ciphertext = 1088;
  static const int mlkem768SharedSecret = 32;

  // Concatenated hybrid sizes.
  static const int hybridPublicKey = x25519PublicKey + mlkem768PublicKey; // 1216
  static const int hybridPrivateKey =
      x25519PrivateKey + mlkem768SecretKey; // 2432
  static const int hybridCiphertext =
      x25519Ciphertext + mlkem768Ciphertext; // 1120
  static const int sharedSecret = 32;
}

/// Suite identifier matching the SK PQC-MIGRATION plan and TLS naming.
const String kSuiteId = 'x25519-mlkem768';

/// Thrown when a key or ciphertext does not match the expected wire layout, or
/// when a backend primitive rejects malformed input. Never crashes the VM —
/// callers can catch this for graceful failure handling.
class SkPqcError implements Exception {
  final String message;
  const SkPqcError(this.message);
  @override
  String toString() => 'SkPqcError: $message';
}
