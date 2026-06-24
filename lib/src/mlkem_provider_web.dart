import 'dart:js_interop';
import 'dart:typed_data';

import 'mlkem_backend.dart';

/// Returns the noble-post-quantum-backed web ML-KEM-768 implementation.
///
/// The audited lattice impl is `@noble/post-quantum`'s `ml_kem768`. It must be
/// exposed to Dart on the JS global as `globalThis.skPqc`, an object with:
///
/// ```js
/// import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
/// globalThis.skPqc = {
///   keygen()            { const k = ml_kem768.keygen();
///                         return { publicKey: k.publicKey, secretKey: k.secretKey }; },
///   encapsulate(pk)     { const e = ml_kem768.encapsulate(pk);
///                         return { cipherText: e.cipherText, sharedSecret: e.sharedSecret }; },
///   decapsulate(ct, sk) { return ml_kem768.decapsulate(ct, sk); },
/// };
/// ```
///
/// See `web/sk_pqc_noble_bootstrap.js` (provided in the package) for a ready
/// bundle; the README documents bundling/CDN/asset delivery.
MlKem768Backend createMlKem768BackendImpl() => NobleMlKem768();

@JS('skPqc')
external _SkPqcJs? get _skPqc;

extension type _SkPqcJs._(JSObject _) implements JSObject {
  external _NobleKeyPair keygen();
  external _NobleEncap encapsulate(JSUint8Array publicKey);
  external JSUint8Array decapsulate(JSUint8Array ciphertext, JSUint8Array secretKey);
}

extension type _NobleKeyPair._(JSObject _) implements JSObject {
  external JSUint8Array get publicKey;
  external JSUint8Array get secretKey;
}

extension type _NobleEncap._(JSObject _) implements JSObject {
  external JSUint8Array get cipherText;
  external JSUint8Array get sharedSecret;
}

/// noble-post-quantum-backed ML-KEM-768 (web). Binds the audited pure-JS impl
/// via `dart:js_interop`.
class NobleMlKem768 extends MlKem768Backend {
  _SkPqcJs get _js {
    final js = _skPqc;
    if (js == null) {
      throw StateError(
        'sk_pqc: globalThis.skPqc is not defined. Bundle '
        '@noble/post-quantum and expose ml_kem768 as globalThis.skPqc '
        '(see web/sk_pqc_noble_bootstrap.js).',
      );
    }
    return js;
  }

  @override
  String get implName => 'noble-post-quantum/ml_kem768';

  @override
  Future<(Uint8List, Uint8List)> keygen() async {
    final kp = _js.keygen();
    return (kp.publicKey.toDart, kp.secretKey.toDart);
  }

  @override
  Future<(Uint8List, Uint8List)> encapsulate(Uint8List publicKey) async {
    final e = _js.encapsulate(publicKey.toJS);
    return (e.cipherText.toDart, e.sharedSecret.toDart);
  }

  @override
  Future<Uint8List> decapsulate(
      Uint8List ciphertext, Uint8List secretKey) async {
    final ss = _js.decapsulate(ciphertext.toJS, secretKey.toJS);
    return ss.toDart;
  }
}
