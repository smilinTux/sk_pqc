import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'mlkem_backend.dart';

/// Returns the liboqs-backed native ML-KEM-768 implementation.
MlKem768Backend createMlKem768BackendImpl() => LiboqsMlKem768();

// ---------------------------------------------------------------------------
// liboqs OQS_KEM C ABI (subset we need). The lattice math lives in liboqs
// (audited); we only declare the C signatures and marshal bytes.
// ---------------------------------------------------------------------------

// typedef struct OQS_KEM { ... } OQS_KEM;
// We treat OQS_KEM* as an opaque pointer and read the size fields by offset.
//
// struct layout (liboqs 0.x, stable public ABI — see src/kem/kem.h):
//   const char *method_name;        // offset 0   (8 B ptr)
//   const char *alg_version;        // offset 8   (8 B ptr)
//   uint8_t claimed_nist_level;     // offset 16
//   bool ind_cca;                   // offset 17
//   size_t length_public_key;       // offset 24 (aligned)
//   size_t length_secret_key;       // offset 32
//   size_t length_ciphertext;       // offset 40
//   size_t length_shared_secret;    // offset 48
//   size_t length_keypair_seed;     // offset 56
//   ... function pointers ...
//
// Rather than depend on exact offsets, we hard-code the FIPS 203 ML-KEM-768
// sizes (which are fixed by the standard) and only call the functions.

typedef _OqsKemNewC = Pointer<Void> Function(Pointer<Utf8>);
typedef _OqsKemNewDart = Pointer<Void> Function(Pointer<Utf8>);

typedef _OqsKemFreeC = Void Function(Pointer<Void>);
typedef _OqsKemFreeDart = void Function(Pointer<Void>);

typedef _OqsKemKeypairC = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _OqsKemKeypairDart = int Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);

typedef _OqsKemEncapsC = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _OqsKemEncapsDart = int Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

typedef _OqsKemDecapsC = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _OqsKemDecapsDart = int Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

const int _oqsSuccess = 0;
const String _algName = 'ML-KEM-768';

// FIPS 203 fixed sizes (ML-KEM-768).
const int _pkLen = 1184;
const int _skLen = 2400;
const int _ctLen = 1088;
const int _ssLen = 32;

class _Liboqs {
  final DynamicLibrary lib;
  late final _OqsKemNewDart kemNew =
      lib.lookupFunction<_OqsKemNewC, _OqsKemNewDart>('OQS_KEM_new');
  late final _OqsKemFreeDart kemFree =
      lib.lookupFunction<_OqsKemFreeC, _OqsKemFreeDart>('OQS_KEM_free');
  late final _OqsKemKeypairDart kemKeypair =
      lib.lookupFunction<_OqsKemKeypairC, _OqsKemKeypairDart>(
          'OQS_KEM_keypair');
  late final _OqsKemEncapsDart kemEncaps =
      lib.lookupFunction<_OqsKemEncapsC, _OqsKemEncapsDart>('OQS_KEM_encaps');
  late final _OqsKemDecapsDart kemDecaps =
      lib.lookupFunction<_OqsKemDecapsC, _OqsKemDecapsDart>('OQS_KEM_decaps');

  _Liboqs(this.lib);
}

DynamicLibrary _openLiboqs() {
  // Candidate names/paths, most specific first. Override with SK_PQC_LIBOQS.
  final env = Platform.environment['SK_PQC_LIBOQS'];
  final candidates = <String>[
    if (env != null && env.isNotEmpty) env,
    if (Platform.isMacOS) 'liboqs.dylib',
    if (Platform.isMacOS) 'liboqs.5.dylib',
    if (Platform.isWindows) 'oqs.dll',
    if (Platform.isWindows) 'liboqs.dll',
    'liboqs.so',
    'liboqs.so.0',
    'liboqs.so.5',
    '${Platform.environment['HOME'] ?? ''}/.local/lib/liboqs.so',
    '/usr/local/lib/liboqs.so',
    '/usr/lib/liboqs.so',
  ];
  Object? lastErr;
  for (final c in candidates) {
    if (c.isEmpty) continue;
    try {
      return DynamicLibrary.open(c);
    } catch (e) {
      lastErr = e;
    }
  }
  throw StateError(
    'sk_pqc: could not load liboqs. Tried: ${candidates.where((c) => c.isNotEmpty).join(", ")}. '
    'Install liboqs (>=0.10, ML-KEM-768) or set SK_PQC_LIBOQS to its path. '
    'Last error: $lastErr',
  );
}

/// liboqs-backed ML-KEM-768. Binds the audited OQS_KEM C API via dart:ffi.
class LiboqsMlKem768 extends MlKem768Backend {
  final _Liboqs _oqs;
  LiboqsMlKem768() : _oqs = _Liboqs(_openLiboqs());

  @override
  String get implName => 'liboqs/OQS_KEM($_algName)';

  Pointer<Void> _newKem() {
    final namePtr = _algName.toNativeUtf8();
    try {
      final kem = _oqs.kemNew(namePtr);
      if (kem == nullptr) {
        throw StateError(
          'sk_pqc: OQS_KEM_new("$_algName") returned NULL — liboqs lacks '
          'ML-KEM-768 (build with OQS_ENABLE_KEM_ml_kem_768).',
        );
      }
      return kem;
    } finally {
      malloc.free(namePtr);
    }
  }

  @override
  Future<(Uint8List, Uint8List)> keygen() async {
    final kem = _newKem();
    final pk = malloc<Uint8>(_pkLen);
    final sk = malloc<Uint8>(_skLen);
    try {
      final rc = _oqs.kemKeypair(kem, pk, sk);
      if (rc != _oqsSuccess) {
        throw StateError('sk_pqc: OQS_KEM_keypair failed (rc=$rc)');
      }
      return (
        Uint8List.fromList(pk.asTypedList(_pkLen)),
        Uint8List.fromList(sk.asTypedList(_skLen)),
      );
    } finally {
      malloc.free(pk);
      malloc.free(sk);
      _oqs.kemFree(kem);
    }
  }

  @override
  Future<(Uint8List, Uint8List)> encapsulate(Uint8List publicKey) async {
    if (publicKey.length != _pkLen) {
      throw ArgumentError(
          'sk_pqc: ML-KEM-768 public key must be $_pkLen bytes');
    }
    final kem = _newKem();
    final pk = malloc<Uint8>(_pkLen);
    final ct = malloc<Uint8>(_ctLen);
    final ss = malloc<Uint8>(_ssLen);
    try {
      pk.asTypedList(_pkLen).setAll(0, publicKey);
      final rc = _oqs.kemEncaps(kem, ct, ss, pk);
      if (rc != _oqsSuccess) {
        throw StateError('sk_pqc: OQS_KEM_encaps failed (rc=$rc)');
      }
      return (
        Uint8List.fromList(ct.asTypedList(_ctLen)),
        Uint8List.fromList(ss.asTypedList(_ssLen)),
      );
    } finally {
      malloc.free(pk);
      malloc.free(ct);
      malloc.free(ss);
      _oqs.kemFree(kem);
    }
  }

  @override
  Future<Uint8List> decapsulate(
      Uint8List ciphertext, Uint8List secretKey) async {
    if (ciphertext.length != _ctLen) {
      throw ArgumentError(
          'sk_pqc: ML-KEM-768 ciphertext must be $_ctLen bytes');
    }
    if (secretKey.length != _skLen) {
      throw ArgumentError(
          'sk_pqc: ML-KEM-768 secret key must be $_skLen bytes');
    }
    final kem = _newKem();
    final ct = malloc<Uint8>(_ctLen);
    final sk = malloc<Uint8>(_skLen);
    final ss = malloc<Uint8>(_ssLen);
    try {
      ct.asTypedList(_ctLen).setAll(0, ciphertext);
      sk.asTypedList(_skLen).setAll(0, secretKey);
      final rc = _oqs.kemDecaps(kem, ss, ct, sk);
      if (rc != _oqsSuccess) {
        // FIPS 203 implicit rejection happens inside liboqs and still returns
        // success with a pseudo-random ss; a nonzero rc is a real error.
        throw StateError('sk_pqc: OQS_KEM_decaps failed (rc=$rc)');
      }
      return Uint8List.fromList(ss.asTypedList(_ssLen));
    } finally {
      malloc.free(ct);
      malloc.free(sk);
      malloc.free(ss);
      _oqs.kemFree(kem);
    }
  }
}
