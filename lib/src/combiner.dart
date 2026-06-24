import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'types.dart';

/// The hybrid combiner — THE ONLY ORIGINAL CRYPTOGRAPHIC CODE in this package.
///
/// Construction (never deviate — concatenate-then-KDF, never XOR, never
/// pure-PQ):
///
/// ```
/// shared_secret = HKDF-SHA256( IKM = X25519_ss ‖ MLKEM768_ss,
///                              salt, info, L = 32 )
/// ```
///
/// `‖` is byte concatenation, X25519 part first. This matches TLS
/// `X25519MLKEM768` and Signal PQXDH style hybrid KEMs. The result is secure if
/// EITHER X25519 or ML-KEM-768 holds.
///
/// HKDF itself is a vetted primitive provided by `package:cryptography`
/// (RFC 5869). We do not implement HKDF — we only define the IKM ordering and
/// the salt/info labels, which are tested against hand-computed vectors.
class HybridCombiner {
  /// Default info label for the combiner. Callers SHOULD pass a
  /// context-specific label (e.g. a channel id) for domain separation. The
  /// default keeps cross-implementation vectors stable.
  static const String defaultInfo = 'sk_pqc/x25519-mlkem768/v1';

  /// Default salt. RFC 5869 permits an empty salt (treated as HashLen zeros).
  /// We use an empty salt by default so the contract is unambiguous; callers
  /// may override.
  static final Uint8List defaultSalt = Uint8List(0);

  /// Combine the two leg shared secrets into the 32-byte hybrid secret.
  ///
  /// [x25519SharedSecret] and [mlkem768SharedSecret] are each 32 bytes.
  /// [salt] and [info] default to [defaultSalt] / [defaultInfo].
  static Future<Uint8List> combine({
    required Uint8List x25519SharedSecret,
    required Uint8List mlkem768SharedSecret,
    Uint8List? salt,
    String info = defaultInfo,
  }) async {
    if (x25519SharedSecret.length != SkPqcSizes.x25519SharedSecret) {
      throw SkPqcError(
        'x25519 shared secret must be ${SkPqcSizes.x25519SharedSecret} bytes, '
        'got ${x25519SharedSecret.length}',
      );
    }
    if (mlkem768SharedSecret.length != SkPqcSizes.mlkem768SharedSecret) {
      throw SkPqcError(
        'ML-KEM-768 shared secret must be '
        '${SkPqcSizes.mlkem768SharedSecret} bytes, '
        'got ${mlkem768SharedSecret.length}',
      );
    }

    // IKM = X25519_ss ‖ MLKEM768_ss  (X25519 first).
    final ikm = Uint8List(
      x25519SharedSecret.length + mlkem768SharedSecret.length,
    )
      ..setAll(0, x25519SharedSecret)
      ..setAll(x25519SharedSecret.length, mlkem768SharedSecret);

    final hkdf = Hkdf(
      hmac: Hmac.sha256(),
      outputLength: SkPqcSizes.sharedSecret,
    );

    final out = await hkdf.deriveKey(
      secretKey: SecretKey(ikm),
      nonce: salt ?? defaultSalt, // `cryptography` calls the HKDF salt `nonce`.
      info: _utf8(info),
    );
    final bytes = await out.extractBytes();
    return Uint8List.fromList(bytes);
  }

  static List<int> _utf8(String s) => s.codeUnits.any((c) => c > 0x7f)
      ? _slowUtf8(s)
      : s.codeUnits;

  static List<int> _slowUtf8(String s) {
    // Lazy import-free UTF-8 for non-ASCII info labels.
    final out = <int>[];
    for (final r in s.runes) {
      if (r <= 0x7f) {
        out.add(r);
      } else if (r <= 0x7ff) {
        out.add(0xc0 | (r >> 6));
        out.add(0x80 | (r & 0x3f));
      } else if (r <= 0xffff) {
        out.add(0xe0 | (r >> 12));
        out.add(0x80 | ((r >> 6) & 0x3f));
        out.add(0x80 | (r & 0x3f));
      } else {
        out.add(0xf0 | (r >> 18));
        out.add(0x80 | ((r >> 12) & 0x3f));
        out.add(0x80 | ((r >> 6) & 0x3f));
        out.add(0x80 | (r & 0x3f));
      }
    }
    return out;
  }
}
