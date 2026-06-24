import 'dart:typed_data';

import 'types.dart';

/// The public hybrid KEM interface. One Dart API, two backends (web JS-interop
/// to noble-post-quantum; native FFI to liboqs) selected by conditional import.
///
/// Suite: `x25519-mlkem768` (see [kSuiteId]).
///
/// Wire layout (interop contract — identical across backends and the Python
/// reference impl):
///
/// - public key  = `X25519_pub (32) ‖ MLKEM768_pub (1184)` = 1216 B
/// - private key = `X25519_priv (32) ‖ MLKEM768_secret (2400)` = 2432 B
/// - ciphertext  = `X25519_eph_pub (32) ‖ MLKEM768_ct (1088)` = 1120 B
/// - shared secret = `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` = 32 B
///
/// The X25519 leg is turned into a KEM via ephemeral-static Diffie–Hellman
/// (DHKEM-style, as in HPKE/TLS): the encapsulator generates a fresh ephemeral
/// X25519 keypair, computes `ss = DH(eph_priv, peer_static_pub)`, and ships the
/// ephemeral public key as the X25519 "ciphertext".
abstract class HybridKem {
  /// Suite identifier.
  String get suiteId => kSuiteId;

  /// The info label fed to the HKDF combiner. Override for domain separation.
  String get info;

  /// Generate a fresh hybrid keypair.
  Future<HybridKeyPair> generateKeyPair();

  /// Encapsulate to [peerPublicKey] (1216 B). Returns the 1120-B ciphertext and
  /// the 32-B shared secret. Throws [SkPqcError] on malformed input.
  Future<EncapResult> encapsulate(Uint8List peerPublicKey);

  /// Decapsulate [ciphertext] (1120 B) with [privateKey] (2432 B). Returns the
  /// 32-B shared secret. Throws [SkPqcError] on malformed input.
  ///
  /// NOTE: ML-KEM uses implicit rejection (FIPS 203 / Fujisaki–Okamoto): a
  /// malformed ML-KEM ciphertext does NOT throw — it yields a pseudo-random
  /// shared secret that will simply not match the encapsulator's. Only
  /// length/format errors throw.
  Future<Uint8List> decapsulate(Uint8List ciphertext, Uint8List privateKey);
}

/// Internal helpers shared by both backends: split/join the concatenated wire
/// format and validate lengths. Kept backend-agnostic.
class WireFormat {
  WireFormat._();

  static (Uint8List x25519, Uint8List mlkem) splitPublicKey(Uint8List pk) {
    if (pk.length != SkPqcSizes.hybridPublicKey) {
      throw SkPqcError(
        'public key must be ${SkPqcSizes.hybridPublicKey} bytes, '
        'got ${pk.length}',
      );
    }
    return (
      Uint8List.sublistView(pk, 0, SkPqcSizes.x25519PublicKey),
      Uint8List.sublistView(pk, SkPqcSizes.x25519PublicKey),
    );
  }

  static (Uint8List x25519, Uint8List mlkem) splitPrivateKey(Uint8List sk) {
    if (sk.length != SkPqcSizes.hybridPrivateKey) {
      throw SkPqcError(
        'private key must be ${SkPqcSizes.hybridPrivateKey} bytes, '
        'got ${sk.length}',
      );
    }
    return (
      Uint8List.sublistView(sk, 0, SkPqcSizes.x25519PrivateKey),
      Uint8List.sublistView(sk, SkPqcSizes.x25519PrivateKey),
    );
  }

  static (Uint8List x25519, Uint8List mlkem) splitCiphertext(Uint8List ct) {
    if (ct.length != SkPqcSizes.hybridCiphertext) {
      throw SkPqcError(
        'ciphertext must be ${SkPqcSizes.hybridCiphertext} bytes, '
        'got ${ct.length}',
      );
    }
    return (
      Uint8List.sublistView(ct, 0, SkPqcSizes.x25519Ciphertext),
      Uint8List.sublistView(ct, SkPqcSizes.x25519Ciphertext),
    );
  }

  static Uint8List join(Uint8List a, Uint8List b) {
    final out = Uint8List(a.length + b.length)
      ..setAll(0, a)
      ..setAll(a.length, b);
    return out;
  }
}
