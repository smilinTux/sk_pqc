import 'dart:typed_data';

import 'combiner.dart';
import 'hybrid_kem.dart';
import 'mlkem_backend.dart';
import 'mlkem_provider.dart';
import 'types.dart';
import 'x25519_kem.dart';

/// The default [HybridKem] implementation. Composes the X25519 KEM leg
/// (`package:cryptography`), the ML-KEM-768 leg (platform-selected audited
/// backend), and the [HybridCombiner] (HKDF-SHA256). Backend-agnostic: the only
/// thing that differs web↔native is [_mlkem].
class HybridKemImpl extends HybridKem {
  final MlKem768Backend _mlkem;

  @override
  final String info;

  /// The HKDF salt (empty by default — see [HybridCombiner.defaultSalt]).
  final Uint8List? salt;

  HybridKemImpl({
    MlKem768Backend? mlkemBackend,
    this.info = HybridCombiner.defaultInfo,
    this.salt,
  }) : _mlkem = mlkemBackend ?? createMlKem768Backend();

  /// Name of the bound ML-KEM implementation (for self-report / debugging).
  String get mlkemImplName => _mlkem.implName;

  @override
  Future<HybridKeyPair> generateKeyPair() async {
    final (xPriv, xPub) = await X25519Kem.generateKeyPair();
    final (mPub, mSec) = await _mlkem.keygen();
    return HybridKeyPair(
      publicKey: WireFormat.join(xPub, mPub),
      privateKey: WireFormat.join(xPriv, mSec),
    );
  }

  @override
  Future<EncapResult> encapsulate(Uint8List peerPublicKey) async {
    final (xPeerPub, mPeerPub) = WireFormat.splitPublicKey(peerPublicKey);
    final (xCt, xSs) = await X25519Kem.encapsulate(xPeerPub);
    final (mCt, mSs) = await _mlkem.encapsulate(mPeerPub);
    final ss = await HybridCombiner.combine(
      x25519SharedSecret: xSs,
      mlkem768SharedSecret: mSs,
      salt: salt,
      info: info,
    );
    return EncapResult(
      ciphertext: WireFormat.join(xCt, mCt),
      sharedSecret: ss,
    );
  }

  @override
  Future<Uint8List> decapsulate(
    Uint8List ciphertext,
    Uint8List privateKey,
  ) async {
    final (xCt, mCt) = WireFormat.splitCiphertext(ciphertext);
    final (xPriv, mSec) = WireFormat.splitPrivateKey(privateKey);
    final xSs = await X25519Kem.decapsulate(xCt, xPriv);
    final mSs = await _mlkem.decapsulate(mCt, mSec);
    return HybridCombiner.combine(
      x25519SharedSecret: xSs,
      mlkem768SharedSecret: mSs,
      salt: salt,
      info: info,
    );
  }
}
