/*
 * _bsv_native — CPython C extension for bsv-sdk
 *
 * Statically links libsecp256k1 and exposes:
 *   - SHA256 / hash256 (double-SHA256)
 *   - ECDSA sign / verify / recover
 *   - Public key operations (create, parse, serialize, combine, tweak)
 *   - ECDH
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

/* ---------- libsecp256k1 configuration (before including the source) ------ */
#define SECP256K1_BUILD          1
#define ECMULT_WINDOW_SIZE      15
#define ECMULT_GEN_PREC_BITS     4
#define ENABLE_MODULE_RECOVERY   1
#define ENABLE_MODULE_ECDH       1
#define ENABLE_MODULE_SCHNORRSIG 1
#define ENABLE_MODULE_EXTRAKEYS  1

/* Include precomputed tables first, then the single-file amalgamation */
#include "secp256k1/src/precomputed_ecmult.c"
#include "secp256k1/src/precomputed_ecmult_gen.c"
#include "secp256k1/src/secp256k1.c"

/* ========================= Global Context ================================ */

static secp256k1_context *g_ctx = NULL;

static int ensure_context(void) {
    if (g_ctx == NULL) {
        g_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
        );
        if (g_ctx == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to create secp256k1 context");
            return 0;
        }
        /* Randomize context for side-channel protection */
        unsigned char seed[32];
        /* Use Python's os.urandom via C API for seeding */
        PyObject *os_mod = PyImport_ImportModule("os");
        if (os_mod) {
            PyObject *urandom = PyObject_CallMethod(os_mod, "urandom", "i", 32);
            if (urandom && PyBytes_Check(urandom)) {
                memcpy(seed, PyBytes_AS_STRING(urandom), 32);
                secp256k1_context_randomize(g_ctx, seed);
                /* Clear seed from stack */
                memset(seed, 0, 32);
            }
            Py_XDECREF(urandom);
            Py_DECREF(os_mod);
        }
    }
    return 1;
}

/* ========================= SHA256 / hash256 ============================== */

static PyObject* pyfn_sha256(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    unsigned char out[32];
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (const unsigned char *)buf.buf, buf.len);
    secp256k1_sha256_finalize(&hasher, out);

    PyBuffer_Release(&buf);
    return PyBytes_FromStringAndSize((const char *)out, 32);
}

static PyObject* pyfn_hash256(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    unsigned char mid[32], out[32];
    secp256k1_sha256 hasher;

    /* First SHA256 */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (const unsigned char *)buf.buf, buf.len);
    secp256k1_sha256_finalize(&hasher, mid);

    /* Second SHA256 */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, mid, 32);
    secp256k1_sha256_finalize(&hasher, out);

    PyBuffer_Release(&buf);
    return PyBytes_FromStringAndSize((const char *)out, 32);
}

static PyObject* pyfn_hmac_sha256(PyObject *self, PyObject *args) {
    Py_buffer key_buf, data_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &key_buf, &data_buf))
        return NULL;

    unsigned char out[32];
    secp256k1_hmac_sha256 hasher;
    secp256k1_hmac_sha256_initialize(&hasher,
        (const unsigned char *)key_buf.buf, key_buf.len);
    secp256k1_hmac_sha256_write(&hasher,
        (const unsigned char *)data_buf.buf, data_buf.len);
    secp256k1_hmac_sha256_finalize(&hasher, out);

    PyBuffer_Release(&key_buf);
    PyBuffer_Release(&data_buf);
    return PyBytes_FromStringAndSize((const char *)out, 32);
}

/* ========================= Public Key Operations ========================= */

static PyObject* pyfn_pubkey_from_secret(PyObject *self, PyObject *args) {
    Py_buffer secret_buf;
    int compressed = 1;
    if (!PyArg_ParseTuple(args, "y*|p", &secret_buf, &compressed))
        return NULL;

    if (secret_buf.len != 32) {
        PyBuffer_Release(&secret_buf);
        PyErr_SetString(PyExc_ValueError, "secret key must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&secret_buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(g_ctx, &pubkey,
            (const unsigned char *)secret_buf.buf)) {
        PyBuffer_Release(&secret_buf);
        PyErr_SetString(PyExc_ValueError, "invalid secret key");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = compressed ? 33 : 65;
    unsigned int flags = compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);

    PyBuffer_Release(&secret_buf);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

static PyObject* pyfn_pubkey_parse(PyObject *self, PyObject *args) {
    Py_buffer buf;
    int compressed = -1;  /* -1 = keep original format */
    if (!PyArg_ParseTuple(args, "y*|i", &buf, &compressed))
        return NULL;

    if (buf.len != 33 && buf.len != 65) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError,
            "public key must be 33 (compressed) or 65 (uncompressed) bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)buf.buf, buf.len)) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    /* Determine output format */
    int out_compressed;
    if (compressed == -1) {
        out_compressed = (buf.len == 33);
    } else {
        out_compressed = compressed;
    }

    unsigned char out[65];
    size_t outlen = out_compressed ? 33 : 65;
    unsigned int flags = out_compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);

    PyBuffer_Release(&buf);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

static PyObject* pyfn_pubkey_serialize(PyObject *self, PyObject *args) {
    Py_buffer buf;
    int compressed = 1;
    if (!PyArg_ParseTuple(args, "y*|p", &buf, &compressed))
        return NULL;

    if (buf.len != 33 && buf.len != 65) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError,
            "public key must be 33 or 65 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)buf.buf, buf.len)) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = compressed ? 33 : 65;
    unsigned int flags = compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);

    PyBuffer_Release(&buf);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

/* pubkey_point: parse pubkey → return (x: int, y: int) */
static PyObject* pyfn_pubkey_point(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    if (buf.len != 33 && buf.len != 65) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "public key must be 33 or 65 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)buf.buf, buf.len)) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = 65;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey,
        SECP256K1_EC_UNCOMPRESSED);

    /* out[0] = 0x04, out[1..32] = x, out[33..64] = y */
    PyObject *x = PyLong_FromUnsignedLongLong(0);
    PyObject *y = PyLong_FromUnsignedLongLong(0);

    /* Build big integers from bytes */
    x = _PyLong_FromByteArray(out + 1, 32, 0 /* big-endian */, 0 /* unsigned */);
    y = _PyLong_FromByteArray(out + 33, 32, 0 /* big-endian */, 0 /* unsigned */);

    PyBuffer_Release(&buf);

    if (!x || !y) {
        Py_XDECREF(x);
        Py_XDECREF(y);
        return NULL;
    }

    PyObject *tuple = PyTuple_Pack(2, x, y);
    Py_DECREF(x);
    Py_DECREF(y);
    return tuple;
}

static PyObject* pyfn_pubkey_combine(PyObject *self, PyObject *args) {
    PyObject *list;
    int compressed = 1;
    if (!PyArg_ParseTuple(args, "O|p", &list, &compressed))
        return NULL;

    if (!PyList_Check(list)) {
        PyErr_SetString(PyExc_TypeError, "first argument must be a list of public key bytes");
        return NULL;
    }

    Py_ssize_t n = PyList_Size(list);
    if (n < 2) {
        PyErr_SetString(PyExc_ValueError, "need at least 2 public keys to combine");
        return NULL;
    }
    if (n > 1024) {
        PyErr_SetString(PyExc_ValueError, "too many public keys");
        return NULL;
    }

    if (!ensure_context())
        return NULL;

    secp256k1_pubkey *pubkeys = (secp256k1_pubkey *)PyMem_Malloc(
        n * sizeof(secp256k1_pubkey));
    const secp256k1_pubkey **ptrs = (const secp256k1_pubkey **)PyMem_Malloc(
        n * sizeof(secp256k1_pubkey *));
    if (!pubkeys || !ptrs) {
        PyMem_Free(pubkeys);
        PyMem_Free(ptrs);
        return PyErr_NoMemory();
    }

    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PyList_GET_ITEM(list, i);
        Py_buffer item_buf;
        if (PyObject_GetBuffer(item, &item_buf, PyBUF_SIMPLE) < 0) {
            PyMem_Free(pubkeys);
            PyMem_Free(ptrs);
            return NULL;
        }
        if (item_buf.len != 33 && item_buf.len != 65) {
            PyBuffer_Release(&item_buf);
            PyMem_Free(pubkeys);
            PyMem_Free(ptrs);
            PyErr_SetString(PyExc_ValueError, "each public key must be 33 or 65 bytes");
            return NULL;
        }
        if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkeys[i],
                (const unsigned char *)item_buf.buf, item_buf.len)) {
            PyBuffer_Release(&item_buf);
            PyMem_Free(pubkeys);
            PyMem_Free(ptrs);
            PyErr_SetString(PyExc_ValueError, "invalid public key in list");
            return NULL;
        }
        ptrs[i] = &pubkeys[i];
        PyBuffer_Release(&item_buf);
    }

    secp256k1_pubkey combined;
    if (!secp256k1_ec_pubkey_combine(g_ctx, &combined, ptrs, n)) {
        PyMem_Free(pubkeys);
        PyMem_Free(ptrs);
        PyErr_SetString(PyExc_ValueError, "failed to combine public keys");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = compressed ? 33 : 65;
    unsigned int flags = compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &combined, flags);

    PyMem_Free(pubkeys);
    PyMem_Free(ptrs);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

static PyObject* pyfn_pubkey_tweak_mul(PyObject *self, PyObject *args) {
    Py_buffer pk_buf, scalar_buf;
    int compressed = 1;
    if (!PyArg_ParseTuple(args, "y*y*|p", &pk_buf, &scalar_buf, &compressed))
        return NULL;

    if ((pk_buf.len != 33 && pk_buf.len != 65) || scalar_buf.len != 32) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        PyErr_SetString(PyExc_ValueError,
            "public key must be 33/65 bytes, scalar must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)pk_buf.buf, pk_buf.len)) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    if (!secp256k1_ec_pubkey_tweak_mul(g_ctx, &pubkey,
            (const unsigned char *)scalar_buf.buf)) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        PyErr_SetString(PyExc_ValueError, "scalar multiplication failed");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = compressed ? 33 : 65;
    unsigned int flags = compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);

    PyBuffer_Release(&pk_buf);
    PyBuffer_Release(&scalar_buf);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

static PyObject* pyfn_pubkey_tweak_add(PyObject *self, PyObject *args) {
    Py_buffer pk_buf, scalar_buf;
    int compressed = 1;
    if (!PyArg_ParseTuple(args, "y*y*|p", &pk_buf, &scalar_buf, &compressed))
        return NULL;

    if ((pk_buf.len != 33 && pk_buf.len != 65) || scalar_buf.len != 32) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        PyErr_SetString(PyExc_ValueError,
            "public key must be 33/65 bytes, scalar must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)pk_buf.buf, pk_buf.len)) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    if (!secp256k1_ec_pubkey_tweak_add(g_ctx, &pubkey,
            (const unsigned char *)scalar_buf.buf)) {
        PyBuffer_Release(&pk_buf);
        PyBuffer_Release(&scalar_buf);
        PyErr_SetString(PyExc_ValueError, "tweak add failed");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = compressed ? 33 : 65;
    unsigned int flags = compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);

    PyBuffer_Release(&pk_buf);
    PyBuffer_Release(&scalar_buf);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

/* ========================= ECDSA ========================================= */

/*
 * DER encoding helper for ECDSA signatures.
 * Takes a secp256k1_ecdsa_signature and produces DER bytes.
 */
static PyObject* sig_to_der(const secp256k1_ecdsa_signature *sig) {
    unsigned char der[72];
    size_t derlen = 72;
    if (!secp256k1_ecdsa_signature_serialize_der(g_ctx, der, &derlen, sig)) {
        PyErr_SetString(PyExc_RuntimeError, "DER serialization failed");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)der, (Py_ssize_t)derlen);
}

static PyObject* pyfn_ecdsa_sign(PyObject *self, PyObject *args) {
    Py_buffer msg_buf, secret_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &msg_buf, &secret_buf))
        return NULL;

    if (msg_buf.len != 32 || secret_buf.len != 32) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyErr_SetString(PyExc_ValueError,
            "message hash and secret key must each be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        return NULL;
    }

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(g_ctx, &sig,
            (const unsigned char *)msg_buf.buf,
            (const unsigned char *)secret_buf.buf,
            NULL, NULL)) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyErr_SetString(PyExc_ValueError, "signing failed");
        return NULL;
    }

    /* Normalize to low-S */
    secp256k1_ecdsa_signature norm;
    secp256k1_ecdsa_signature_normalize(g_ctx, &norm, &sig);

    PyBuffer_Release(&msg_buf);
    PyBuffer_Release(&secret_buf);
    return sig_to_der(&norm);
}

static PyObject* pyfn_ecdsa_verify(PyObject *self, PyObject *args) {
    Py_buffer sig_buf, msg_buf, pk_buf;
    if (!PyArg_ParseTuple(args, "y*y*y*", &sig_buf, &msg_buf, &pk_buf))
        return NULL;

    if (msg_buf.len != 32) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&pk_buf);
        PyErr_SetString(PyExc_ValueError, "message hash must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&pk_buf);
        return NULL;
    }

    /* Parse signature from DER */
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(g_ctx, &sig,
            (const unsigned char *)sig_buf.buf, sig_buf.len)) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&pk_buf);
        PyErr_SetString(PyExc_ValueError, "invalid DER signature");
        return NULL;
    }

    /* Parse public key */
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)pk_buf.buf, pk_buf.len)) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&pk_buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    int result = secp256k1_ecdsa_verify(g_ctx, &sig,
        (const unsigned char *)msg_buf.buf, &pubkey);

    PyBuffer_Release(&sig_buf);
    PyBuffer_Release(&msg_buf);
    PyBuffer_Release(&pk_buf);
    return PyBool_FromLong(result);
}

static PyObject* pyfn_ecdsa_sign_recoverable(PyObject *self, PyObject *args) {
    Py_buffer msg_buf, secret_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &msg_buf, &secret_buf))
        return NULL;

    if (msg_buf.len != 32 || secret_buf.len != 32) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyErr_SetString(PyExc_ValueError,
            "message hash and secret key must each be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        return NULL;
    }

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(g_ctx, &rsig,
            (const unsigned char *)msg_buf.buf,
            (const unsigned char *)secret_buf.buf,
            NULL, NULL)) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyErr_SetString(PyExc_ValueError, "recoverable signing failed");
        return NULL;
    }

    /* Serialize: r (32 bytes) + s (32 bytes) + recovery_id (1 byte) */
    unsigned char out[65];
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(g_ctx, out, &recid, &rsig);

    /* Normalize to low-S */
    /* Check if s > n/2, if so negate s and flip recid */
    secp256k1_ecdsa_signature std_sig;
    secp256k1_ecdsa_recoverable_signature_convert(g_ctx, &std_sig, &rsig);
    secp256k1_ecdsa_signature norm;
    int was_negated = secp256k1_ecdsa_signature_normalize(g_ctx, &norm, &std_sig);
    if (was_negated) {
        /* Re-serialize the normalized signature */
        unsigned char compact[64];
        secp256k1_ecdsa_signature_serialize_compact(g_ctx, compact, &norm);
        memcpy(out, compact, 64);
        recid ^= 1;
    }

    out[64] = (unsigned char)recid;

    PyBuffer_Release(&msg_buf);
    PyBuffer_Release(&secret_buf);
    return PyBytes_FromStringAndSize((const char *)out, 65);
}

static PyObject* pyfn_ecdsa_recover(PyObject *self, PyObject *args) {
    Py_buffer sig_buf, msg_buf;
    int compressed = 1;
    if (!PyArg_ParseTuple(args, "y*y*|p", &sig_buf, &msg_buf, &compressed))
        return NULL;

    if (sig_buf.len != 65) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyErr_SetString(PyExc_ValueError,
            "recoverable signature must be 65 bytes (r32 + s32 + recid1)");
        return NULL;
    }
    if (msg_buf.len != 32) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyErr_SetString(PyExc_ValueError, "message hash must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        return NULL;
    }

    const unsigned char *sigdata = (const unsigned char *)sig_buf.buf;
    int recid = sigdata[64];

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            g_ctx, &rsig, sigdata, recid)) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyErr_SetString(PyExc_ValueError, "invalid recoverable signature");
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(g_ctx, &pubkey, &rsig,
            (const unsigned char *)msg_buf.buf)) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyErr_SetString(PyExc_ValueError, "public key recovery failed");
        return NULL;
    }

    unsigned char out[65];
    size_t outlen = compressed ? 33 : 65;
    unsigned int flags = compressed
        ? SECP256K1_EC_COMPRESSED
        : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);

    PyBuffer_Release(&sig_buf);
    PyBuffer_Release(&msg_buf);
    return PyBytes_FromStringAndSize((const char *)out, (Py_ssize_t)outlen);
}

/* ========================= ECDH ========================================== */

static PyObject* pyfn_ecdh(PyObject *self, PyObject *args) {
    Py_buffer secret_buf, pk_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &secret_buf, &pk_buf))
        return NULL;

    if (secret_buf.len != 32) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&pk_buf);
        PyErr_SetString(PyExc_ValueError, "secret key must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&pk_buf);
        return NULL;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey,
            (const unsigned char *)pk_buf.buf, pk_buf.len)) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&pk_buf);
        PyErr_SetString(PyExc_ValueError, "invalid public key");
        return NULL;
    }

    unsigned char out[32];
    if (!secp256k1_ecdh(g_ctx, out,
            &pubkey, (const unsigned char *)secret_buf.buf,
            NULL, NULL)) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&pk_buf);
        PyErr_SetString(PyExc_ValueError, "ECDH failed");
        return NULL;
    }

    PyBuffer_Release(&secret_buf);
    PyBuffer_Release(&pk_buf);
    return PyBytes_FromStringAndSize((const char *)out, 32);
}

/* ========================= Secret Key Operations ========================= */

static PyObject* pyfn_seckey_verify(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    if (buf.len != 32) {
        PyBuffer_Release(&buf);
        return Py_NewRef(Py_False);
    }

    if (!ensure_context()) {
        PyBuffer_Release(&buf);
        return NULL;
    }

    int result = secp256k1_ec_seckey_verify(g_ctx,
        (const unsigned char *)buf.buf);

    PyBuffer_Release(&buf);
    return PyBool_FromLong(result);
}

static PyObject* pyfn_seckey_tweak_add(PyObject *self, PyObject *args) {
    Py_buffer secret_buf, tweak_buf;
    if (!PyArg_ParseTuple(args, "y*y*", &secret_buf, &tweak_buf))
        return NULL;

    if (secret_buf.len != 32 || tweak_buf.len != 32) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&tweak_buf);
        PyErr_SetString(PyExc_ValueError,
            "secret key and tweak must each be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&tweak_buf);
        return NULL;
    }

    unsigned char result[32];
    memcpy(result, secret_buf.buf, 32);

    if (!secp256k1_ec_seckey_tweak_add(g_ctx, result,
            (const unsigned char *)tweak_buf.buf)) {
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&tweak_buf);
        PyErr_SetString(PyExc_ValueError, "secret key tweak add failed");
        return NULL;
    }

    PyBuffer_Release(&secret_buf);
    PyBuffer_Release(&tweak_buf);
    return PyBytes_FromStringAndSize((const char *)result, 32);
}

/* ========================= Context ======================================= */

static PyObject* pyfn_context_randomize(PyObject *self, PyObject *args) {
    Py_buffer seed_buf;
    if (!PyArg_ParseTuple(args, "y*", &seed_buf))
        return NULL;

    if (seed_buf.len != 32) {
        PyBuffer_Release(&seed_buf);
        PyErr_SetString(PyExc_ValueError, "seed must be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&seed_buf);
        return NULL;
    }

    int result = secp256k1_context_randomize(g_ctx,
        (const unsigned char *)seed_buf.buf);

    PyBuffer_Release(&seed_buf);
    if (!result) {
        PyErr_SetString(PyExc_RuntimeError, "context randomization failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

/* ========================= Module Definition ============================= */

static PyMethodDef bsv_native_methods[] = {
    /* Hash functions */
    {"sha256", pyfn_sha256, METH_VARARGS,
     "sha256(data) -> bytes\n\nCompute SHA-256 hash."},
    {"hash256", pyfn_hash256, METH_VARARGS,
     "hash256(data) -> bytes\n\nCompute double SHA-256 (SHA256d) hash."},
    {"hmac_sha256", pyfn_hmac_sha256, METH_VARARGS,
     "hmac_sha256(key, data) -> bytes\n\nCompute HMAC-SHA256."},

    /* Public key operations */
    {"pubkey_from_secret", pyfn_pubkey_from_secret, METH_VARARGS,
     "pubkey_from_secret(secret32, compressed=True) -> bytes\n\n"
     "Derive public key from 32-byte secret key."},
    {"pubkey_parse", pyfn_pubkey_parse, METH_VARARGS,
     "pubkey_parse(data, compressed=-1) -> bytes\n\n"
     "Parse and re-serialize a public key. compressed=-1 keeps original format."},
    {"pubkey_serialize", pyfn_pubkey_serialize, METH_VARARGS,
     "pubkey_serialize(pubkey, compressed=True) -> bytes\n\n"
     "Serialize a public key to compressed or uncompressed format."},
    {"pubkey_point", pyfn_pubkey_point, METH_VARARGS,
     "pubkey_point(pubkey) -> (x: int, y: int)\n\n"
     "Extract the (x, y) point coordinates from a public key."},
    {"pubkey_combine", pyfn_pubkey_combine, METH_VARARGS,
     "pubkey_combine([pk1, pk2, ...], compressed=True) -> bytes\n\n"
     "Add multiple public keys (EC point addition)."},
    {"pubkey_tweak_mul", pyfn_pubkey_tweak_mul, METH_VARARGS,
     "pubkey_tweak_mul(pubkey, scalar32, compressed=True) -> bytes\n\n"
     "Multiply a public key by a scalar (EC point multiplication)."},
    {"pubkey_tweak_add", pyfn_pubkey_tweak_add, METH_VARARGS,
     "pubkey_tweak_add(pubkey, scalar32, compressed=True) -> bytes\n\n"
     "Add a scalar times the generator to a public key."},

    /* ECDSA */
    {"ecdsa_sign", pyfn_ecdsa_sign, METH_VARARGS,
     "ecdsa_sign(msg32, secret32) -> bytes\n\n"
     "Create a DER-encoded ECDSA signature (low-S normalized)."},
    {"ecdsa_verify", pyfn_ecdsa_verify, METH_VARARGS,
     "ecdsa_verify(sig_der, msg32, pubkey) -> bool\n\n"
     "Verify a DER-encoded ECDSA signature."},
    {"ecdsa_sign_recoverable", pyfn_ecdsa_sign_recoverable, METH_VARARGS,
     "ecdsa_sign_recoverable(msg32, secret32) -> bytes\n\n"
     "Create a recoverable ECDSA signature (r32 + s32 + recid1, 65 bytes)."},
    {"ecdsa_recover", pyfn_ecdsa_recover, METH_VARARGS,
     "ecdsa_recover(sig65, msg32, compressed=True) -> bytes\n\n"
     "Recover a public key from a recoverable signature."},

    /* ECDH */
    {"ecdh", pyfn_ecdh, METH_VARARGS,
     "ecdh(secret32, pubkey) -> bytes\n\n"
     "Compute ECDH shared secret."},

    /* Secret key operations */
    {"seckey_verify", pyfn_seckey_verify, METH_VARARGS,
     "seckey_verify(secret32) -> bool\n\n"
     "Verify that a 32-byte value is a valid secret key."},
    {"seckey_tweak_add", pyfn_seckey_tweak_add, METH_VARARGS,
     "seckey_tweak_add(secret32, tweak32) -> bytes\n\n"
     "Add a tweak to a secret key (constant-time)."},

    /* Context */
    {"context_randomize", pyfn_context_randomize, METH_VARARGS,
     "context_randomize(seed32) -> None\n\n"
     "Re-randomize the secp256k1 context for side-channel protection."},

    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef bsv_native_module = {
    PyModuleDef_HEAD_INIT,
    "_bsv_native",
    "CPython C extension for bsv-sdk: libsecp256k1 integration, SHA256, ECDSA, ECDH.",
    -1,
    bsv_native_methods
};

PyMODINIT_FUNC PyInit__bsv_native(void) {
    PyObject *m = PyModule_Create(&bsv_native_module);
    if (m == NULL)
        return NULL;

    /* Initialize the global secp256k1 context on module load */
    if (!ensure_context()) {
        Py_DECREF(m);
        return NULL;
    }

    /* Add version info */
    if (PyModule_AddStringConstant(m, "__version__", "0.1.0") < 0) {
        Py_DECREF(m);
        return NULL;
    }

    /* Add backend name */
    if (PyModule_AddStringConstant(m, "BACKEND", "libsecp256k1") < 0) {
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
