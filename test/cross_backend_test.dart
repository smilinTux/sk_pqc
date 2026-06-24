@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sk_pqc/sk_pqc.dart';
import 'package:sk_pqc/src/mlkem_provider_ffi.dart';
import 'package:test/test.dart';

String toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _hex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// A [MlKem768Backend] that drives the REAL `@noble/post-quantum` ml_kem768 via
/// a Node helper. This exercises the exact JS library the web backend binds to,
/// so a keypair/encapsulation from "noble" decapsulates under the native liboqs
/// backend and vice-versa — proving cross-backend wire-format + combiner parity
/// from inside the Dart test runner.
class NobleNodeMlKem768 extends MlKem768Backend {
  final String nobleDir;
  NobleNodeMlKem768(this.nobleDir);

  @override
  String get implName => 'noble-post-quantum(node helper)';

  Map<String, dynamic> _run(String op, List<String> hexArgs) {
    final res = Process.runSync(
      'node',
      ['--input-type=module', '-e', _script(op), ...hexArgs],
      workingDirectory: nobleDir,
    );
    if (res.exitCode != 0) {
      throw StateError('noble node helper failed: ${res.stderr}');
    }
    return jsonDecode((res.stdout as String).trim()) as Map<String, dynamic>;
  }

  @override
  Future<(Uint8List, Uint8List)> keygen() async {
    final r = _run('keygen', []);
    return (_hex(r['pk'] as String), _hex(r['sk'] as String));
  }

  @override
  Future<(Uint8List, Uint8List)> encapsulate(Uint8List publicKey) async {
    final r = _run('encaps', [toHex(publicKey)]);
    return (_hex(r['ct'] as String), _hex(r['ss'] as String));
  }

  @override
  Future<Uint8List> decapsulate(
      Uint8List ciphertext, Uint8List secretKey) async {
    final r = _run('decaps', [toHex(ciphertext), toHex(secretKey)]);
    return _hex(r['ss'] as String);
  }

  static String _script(String op) => '''
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
const hex=(h)=>Uint8Array.from(Buffer.from(h,"hex"));
const toHex=(b)=>Buffer.from(b).toString("hex");
const a=process.argv.slice(1);
const op="$op";
let out={};
if(op==="keygen"){const k=ml_kem768.keygen();out={pk:toHex(k.publicKey),sk:toHex(k.secretKey)};}
else if(op==="encaps"){const e=ml_kem768.encapsulate(hex(a[0]));out={ct:toHex(e.cipherText),ss:toHex(e.sharedSecret)};}
else if(op==="decaps"){out={ss:toHex(ml_kem768.decapsulate(hex(a[0]),hex(a[1])))};}
process.stdout.write(JSON.stringify(out));
''';
}

void main() {
  final nobleDir =
      Platform.environment['SK_PQC_NOBLE_DIR'] ?? '/tmp/noble-probe';

  bool nodeNobleAvailable() {
    if (!Directory('$nobleDir/node_modules/@noble/post-quantum').existsSync()) {
      return false;
    }
    try {
      Process.runSync('node', ['--version']);
      return true;
    } catch (_) {
      return false;
    }
  }

  bool liboqsAvailable() {
    try {
      LiboqsMlKem768();
      return true;
    } catch (_) {
      return false;
    }
  }

  final haveBoth = nodeNobleAvailable() && liboqsAvailable();
  final skipReason = haveBoth
      ? null
      : 'needs both liboqs (native) and node + @noble/post-quantum '
          '(set SK_PQC_NOBLE_DIR)';

  group('cross-backend: noble(web lib) <-> liboqs(native)', () {
    late HybridKemImpl native;
    late HybridKemImpl web;

    setUp(() {
      native = HybridKemImpl(mlkemBackend: LiboqsMlKem768());
      web = HybridKemImpl(mlkemBackend: NobleNodeMlKem768(nobleDir));
    });

    test('keypair from native, encapsulate on web, decapsulate on native',
        () async {
      final kp = await native.generateKeyPair();
      final enc = await web.encapsulate(kp.publicKey);
      final ss = await native.decapsulate(enc.ciphertext, kp.privateKey);
      expect(toHex(ss), equals(toHex(enc.sharedSecret)));
    }, skip: skipReason);

    test('keypair from web, encapsulate on native, decapsulate on web',
        () async {
      final kp = await web.generateKeyPair();
      final enc = await native.encapsulate(kp.publicKey);
      final ss = await web.decapsulate(enc.ciphertext, kp.privateKey);
      expect(toHex(ss), equals(toHex(enc.sharedSecret)));
    }, skip: skipReason);

    test('both backends decapsulate the shared interop vector identically',
        () async {
      final v = jsonDecode(
        File('test_vectors/hybrid_kem_x25519_mlkem768.json').readAsStringSync(),
      ) as Map<String, dynamic>;
      final h = v['hybrid'] as Map<String, dynamic>;
      final ct = _hex(h['ciphertext'] as String);
      final sk = _hex(h['private_key'] as String);
      final ssNative = await native.decapsulate(ct, sk);
      final ssWeb = await web.decapsulate(ct, sk);
      expect(toHex(ssNative), equals(h['shared_secret']));
      expect(toHex(ssWeb), equals(h['shared_secret']));
    }, skip: skipReason);
  });
}
