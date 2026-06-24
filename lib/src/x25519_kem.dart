import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'types.dart';

/// X25519 turned into a KEM via ephemeral-static Diffie–Hellman (DHKEM-style).
///
/// X25519 itself is provided by `package:cryptography` (a vetted impl), used by
/// BOTH backends so the classical leg is identical everywhere. We only wire the
/// KEM wrapper (generate ephemeral, DH, ship ephemeral pub) — no curve math is
/// hand-rolled.
class X25519Kem {
  static final X25519 _x = X25519();

  /// Generate a static X25519 keypair. Returns (32-B private, 32-B public).
  static Future<(Uint8List priv, Uint8List pub)> generateKeyPair() async {
    final kp = await _x.newKeyPair();
    final priv = await kp.extractPrivateKeyBytes();
    final pub = (await kp.extractPublicKey()).bytes;
    return (Uint8List.fromList(priv), Uint8List.fromList(pub));
  }

  /// Encapsulate to [peerPublic] (32 B): returns the ephemeral public key
  /// ("ciphertext", 32 B) and the 32-B DH shared secret.
  static Future<(Uint8List ct, Uint8List ss)> encapsulate(
    Uint8List peerPublic,
  ) async {
    if (peerPublic.length != SkPqcSizes.x25519PublicKey) {
      throw SkPqcError(
        'x25519 public key must be ${SkPqcSizes.x25519PublicKey} bytes, '
        'got ${peerPublic.length}',
      );
    }
    final ephKp = await _x.newKeyPair();
    final ephPub = (await ephKp.extractPublicKey()).bytes;
    final ss = await _x.sharedSecretKey(
      keyPair: ephKp,
      remotePublicKey: SimplePublicKey(peerPublic, type: KeyPairType.x25519),
    );
    final ssBytes = await ss.extractBytes();
    return (Uint8List.fromList(ephPub), Uint8List.fromList(ssBytes));
  }

  /// Decapsulate: given the ephemeral public [ct] (32 B) and our static private
  /// key [priv] (32 B), recompute the 32-B DH shared secret.
  static Future<Uint8List> decapsulate(
    Uint8List ct,
    Uint8List priv,
  ) async {
    if (ct.length != SkPqcSizes.x25519Ciphertext) {
      throw SkPqcError(
        'x25519 ciphertext must be ${SkPqcSizes.x25519Ciphertext} bytes, '
        'got ${ct.length}',
      );
    }
    if (priv.length != SkPqcSizes.x25519PrivateKey) {
      throw SkPqcError(
        'x25519 private key must be ${SkPqcSizes.x25519PrivateKey} bytes, '
        'got ${priv.length}',
      );
    }
    final kp = await _x.newKeyPairFromSeed(priv);
    final ss = await _x.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(ct, type: KeyPairType.x25519),
    );
    final ssBytes = await ss.extractBytes();
    return Uint8List.fromList(ssBytes);
  }
}
