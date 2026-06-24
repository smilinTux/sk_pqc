// Compile-only smoke check for the web backend (selects NobleMlKem768 via the
// conditional import on the js_interop platform). Not meant to run — just to
// prove the js_interop code is valid Dart that dart2js accepts.
import 'package:sk_pqc/sk_pqc.dart';

Future<void> main() async {
  final kem = HybridKemImpl(); // resolves to the noble web backend under dart2js
  final kp = await kem.generateKeyPair();
  final enc = await kem.encapsulate(kp.publicKey);
  final ss = await kem.decapsulate(enc.ciphertext, kp.privateKey);
  print('${ss.length} ${kem.mlkemImplName} ${kem.suiteId}');
}
