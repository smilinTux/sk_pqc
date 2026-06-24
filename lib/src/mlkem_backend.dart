import 'dart:typed_data';

/// Abstract ML-KEM-768 (FIPS 203) provider. The lattice primitive is NEVER
/// implemented here — concrete subclasses bind to an AUDITED implementation:
///
/// - native ([io], `dart:ffi`)  → liboqs `OQS_KEM` ML-KEM-768
/// - web  ([web], JS-interop)   → `@noble/post-quantum` ml_kem768
abstract class MlKem768Backend {
  /// Human-readable name of the bound implementation (for self-report).
  String get implName;

  /// Generate a keypair: returns (publicKey 1184 B, secretKey 2400 B).
  Future<(Uint8List pk, Uint8List sk)> keygen();

  /// Encapsulate to [publicKey] (1184 B): returns (ciphertext 1088 B,
  /// sharedSecret 32 B).
  Future<(Uint8List ct, Uint8List ss)> encapsulate(Uint8List publicKey);

  /// Decapsulate [ciphertext] (1088 B) with [secretKey] (2400 B): returns the
  /// 32-B shared secret (implicit-rejection on malformed ct per FIPS 203).
  Future<Uint8List> decapsulate(Uint8List ciphertext, Uint8List secretKey);
}
