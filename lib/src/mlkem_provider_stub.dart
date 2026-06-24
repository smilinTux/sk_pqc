import 'mlkem_backend.dart';

/// Fallback used when neither `dart:ffi` nor `dart:js_interop` is available.
MlKem768Backend createMlKem768BackendImpl() => throw UnsupportedError(
      'sk_pqc: no ML-KEM-768 backend for this platform. '
      'Native requires dart:ffi + liboqs; web requires dart:js_interop + '
      'noble-post-quantum.',
    );
