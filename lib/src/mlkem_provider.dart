// Conditional-import dispatcher for the ML-KEM-768 backend.
//
// On native platforms (dart:ffi available) this resolves to the liboqs FFI
// binding. On web (dart.library.js_interop available) it resolves to the
// noble-post-quantum JS-interop binding. The default stub throws so missing
// platform support is a clear error, never a silent wrong answer.

import 'mlkem_backend.dart';
import 'mlkem_provider_stub.dart'
    if (dart.library.ffi) 'mlkem_provider_ffi.dart'
    if (dart.library.js_interop) 'mlkem_provider_web.dart';

/// Returns the platform's ML-KEM-768 backend (liboqs native / noble web).
MlKem768Backend createMlKem768Backend() => createMlKem768BackendImpl();
