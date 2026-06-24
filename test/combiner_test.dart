import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sk_pqc/sk_pqc.dart';
import 'package:test/test.dart';

Uint8List hex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('HybridCombiner — HKDF-SHA256 vectors', () {
    late Map<String, dynamic> vectors;

    setUpAll(() {
      final f = File('test_vectors/combiner_hkdf.json');
      vectors = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
    });

    test('matches hand-computed combiner vectors (salt/info handling)',
        () async {
      for (final raw in vectors['vectors'] as List) {
        final v = raw as Map<String, dynamic>;
        final name = v['name'] as String;
        // Skip the pure-HKDF RFC sanity entry — combiner takes two 32-B legs.
        if (!v.containsKey('x25519_ss')) continue;

        final got = await HybridCombiner.combine(
          x25519SharedSecret: hex(v['x25519_ss'] as String),
          mlkem768SharedSecret: hex(v['mlkem768_ss'] as String),
          salt: hex(v['salt_hex'] as String),
          info: v['info_utf8'] as String,
        );
        expect(toHex(got), equals(v['expected']),
            reason: 'combiner vector "$name" mismatch');
      }
    });

    test('default info + empty salt matches the documented default', () async {
      final got = await HybridCombiner.combine(
        x25519SharedSecret: Uint8List(32)..fillRange(0, 32, 0x11),
        mlkem768SharedSecret: Uint8List(32)..fillRange(0, 32, 0x22),
      );
      expect(got.length, equals(32));
      expect(toHex(got),
          equals('27b3873917df86c97b9dae40d36efe79e0fee7a868599bf1f0ec8f342a181e87'));
    });

    test('rejects wrong-length leg secrets', () async {
      expect(
        () => HybridCombiner.combine(
          x25519SharedSecret: Uint8List(31),
          mlkem768SharedSecret: Uint8List(32),
        ),
        throwsA(isA<SkPqcError>()),
      );
      expect(
        () => HybridCombiner.combine(
          x25519SharedSecret: Uint8List(32),
          mlkem768SharedSecret: Uint8List(16),
        ),
        throwsA(isA<SkPqcError>()),
      );
    });

    test('different info → different secret (domain separation)', () async {
      final a = await HybridCombiner.combine(
        x25519SharedSecret: Uint8List(32)..fillRange(0, 32, 1),
        mlkem768SharedSecret: Uint8List(32)..fillRange(0, 32, 2),
        info: 'context-a',
      );
      final b = await HybridCombiner.combine(
        x25519SharedSecret: Uint8List(32)..fillRange(0, 32, 1),
        mlkem768SharedSecret: Uint8List(32)..fillRange(0, 32, 2),
        info: 'context-b',
      );
      expect(toHex(a), isNot(equals(toHex(b))));
    });
  });
}
