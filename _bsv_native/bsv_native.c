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

static int nonce_fn_custom_k(unsigned char *nonce32,
                             const unsigned char *msg32,
                             const unsigned char *key32,
                             const unsigned char *algo16,
                             void *data,
                             unsigned int counter) {
    (void)msg32; (void)key32; (void)algo16; (void)counter;
    memcpy(nonce32, data, 32);
    return 1;
}

static PyObject* pyfn_ecdsa_sign_with_k(PyObject *self, PyObject *args) {
    Py_buffer msg_buf, secret_buf, k_buf;
    if (!PyArg_ParseTuple(args, "y*y*y*", &msg_buf, &secret_buf, &k_buf))
        return NULL;

    if (msg_buf.len != 32 || secret_buf.len != 32 || k_buf.len != 32) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&k_buf);
        PyErr_SetString(PyExc_ValueError,
            "msg32, secret32, and k32 must each be 32 bytes");
        return NULL;
    }

    if (!ensure_context()) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&k_buf);
        return NULL;
    }

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(g_ctx, &sig,
            (const unsigned char *)msg_buf.buf,
            (const unsigned char *)secret_buf.buf,
            nonce_fn_custom_k,
            (void *)k_buf.buf)) {
        PyBuffer_Release(&msg_buf);
        PyBuffer_Release(&secret_buf);
        PyBuffer_Release(&k_buf);
        PyErr_SetString(PyExc_ValueError, "signing with custom k failed");
        return NULL;
    }

    secp256k1_ecdsa_signature norm;
    secp256k1_ecdsa_signature_normalize(g_ctx, &norm, &sig);

    PyBuffer_Release(&msg_buf);
    PyBuffer_Release(&secret_buf);
    PyBuffer_Release(&k_buf);
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

    if (recid < 0 || recid > 3) {
        PyBuffer_Release(&sig_buf);
        PyBuffer_Release(&msg_buf);
        PyErr_SetString(PyExc_ValueError, "recovery id must be 0, 1, 2, or 3");
        return NULL;
    }

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

/* ========================= Hex conversion helpers ======================== */

static const char hex_lut[] = "0123456789abcdef";

/* Convert 32 bytes to 64-char hex string (no null terminator) */
static void bytes_to_hex(const unsigned char *src, char *dst, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        dst[i * 2]     = hex_lut[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex_lut[src[i] & 0xF];
    }
}

/* Convert 32 bytes to 64-char hex string, reversed byte order */
static void bytes_to_hex_reversed(const unsigned char *src, char *dst, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        int ri = nbytes - 1 - i;
        dst[i * 2]     = hex_lut[(src[ri] >> 4) & 0xF];
        dst[i * 2 + 1] = hex_lut[src[ri] & 0xF];
    }
}

/* Parse a single hex char to nibble, return -1 on error */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse 64-char hex string to 32 bytes, reversed byte order */
static int hex_to_bytes_reversed(const char *hex, unsigned char *dst, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        int si = (nbytes - 1 - i) * 2;
        int hi = hex_nibble(hex[si]);
        int lo = hex_nibble(hex[si + 1]);
        if (hi < 0 || lo < 0) return -1;
        dst[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

/* Parse hex string to bytes, normal order */
static int hex_to_bytes(const char *hex, unsigned char *dst, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        dst[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

/* ========================= Phase 1: Script Chunks ======================== */

/*
 * parse_script_chunks(script_bytes) -> list[tuple[int, bytes|None]]
 *
 * Each tuple is (opcode, data_or_None). Mirrors ScriptChunk(op, data).
 */
static PyObject* pyfn_parse_script_chunks(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    const unsigned char *s = (const unsigned char *)buf.buf;
    Py_ssize_t n = buf.len;
    Py_ssize_t i = 0;

    PyObject *list = PyList_New(0);
    if (!list) {
        PyBuffer_Release(&buf);
        return NULL;
    }

    while (i < n) {
        unsigned char op = s[i];
        i++;

        PyObject *chunk = NULL;

        if (op <= 75) {
            /* Direct push: op bytes of data follow */
            if (i + op > n) break;
            PyObject *data = PyBytes_FromStringAndSize((const char *)(s + i), op);
            chunk = PyTuple_Pack(2, PyLong_FromLong(op), data);
            Py_DECREF(data);
            i += op;
        } else if (op == 0x4C) {
            /* OP_PUSHDATA1 */
            if (i >= n) break;
            Py_ssize_t ln = s[i]; i++;
            if (i + ln > n) break;
            PyObject *data = PyBytes_FromStringAndSize((const char *)(s + i), ln);
            chunk = PyTuple_Pack(2, PyLong_FromLong(0x4C), data);
            Py_DECREF(data);
            i += ln;
        } else if (op == 0x4D) {
            /* OP_PUSHDATA2 */
            if (i + 2 > n) break;
            Py_ssize_t ln = s[i] | (s[i+1] << 8);
            i += 2;
            if (i + ln > n) break;
            PyObject *data = PyBytes_FromStringAndSize((const char *)(s + i), ln);
            chunk = PyTuple_Pack(2, PyLong_FromLong(0x4D), data);
            Py_DECREF(data);
            i += ln;
        } else if (op == 0x4E) {
            /* OP_PUSHDATA4 */
            if (i + 4 > n) break;
            Py_ssize_t ln = s[i] | (s[i+1] << 8) | (s[i+2] << 16) | ((Py_ssize_t)s[i+3] << 24);
            i += 4;
            if (i + ln > n) break;
            PyObject *data = PyBytes_FromStringAndSize((const char *)(s + i), ln);
            chunk = PyTuple_Pack(2, PyLong_FromLong(0x4E), data);
            Py_DECREF(data);
            i += ln;
        } else {
            /* Non-push opcode */
            chunk = PyTuple_Pack(2, PyLong_FromLong(op), Py_None);
        }

        if (!chunk) {
            Py_DECREF(list);
            PyBuffer_Release(&buf);
            return PyErr_NoMemory();
        }
        if (PyList_Append(list, chunk) < 0) {
            Py_DECREF(chunk);
            Py_DECREF(list);
            PyBuffer_Release(&buf);
            return NULL;
        }
        Py_DECREF(chunk);
    }

    PyBuffer_Release(&buf);
    return list;
}

/*
 * serialize_script_chunks(chunks) -> bytes
 *
 * chunks: list of tuple[int, bytes|None]
 */
static PyObject* pyfn_serialize_script_chunks(PyObject *self, PyObject *args) {
    PyObject *list;
    if (!PyArg_ParseTuple(args, "O", &list))
        return NULL;

    if (!PyList_Check(list)) {
        PyErr_SetString(PyExc_TypeError, "argument must be a list");
        return NULL;
    }

    Py_ssize_t count = PyList_Size(list);

    /* Pre-calculate total size */
    Py_ssize_t total = 0;
    for (Py_ssize_t idx = 0; idx < count; idx++) {
        PyObject *chunk = PyList_GET_ITEM(list, idx);
        if (!PyTuple_Check(chunk) || PyTuple_GET_SIZE(chunk) != 2) {
            PyErr_SetString(PyExc_TypeError, "each chunk must be a (int, bytes|None) tuple");
            return NULL;
        }
        long op = PyLong_AsLong(PyTuple_GET_ITEM(chunk, 0));
        PyObject *data = PyTuple_GET_ITEM(chunk, 1);

        total++; /* opcode byte */
        if (data != Py_None) {
            if (!PyBytes_Check(data)) {
                PyErr_SetString(PyExc_TypeError, "chunk data must be bytes or None");
                return NULL;
            }
            Py_ssize_t dlen = PyBytes_GET_SIZE(data);
            if (op == 0x4C) total += 1;
            else if (op == 0x4D) total += 2;
            else if (op == 0x4E) total += 4;
            total += dlen;
        }
    }

    PyObject *result = PyBytes_FromStringAndSize(NULL, total);
    if (!result) return NULL;
    unsigned char *out = (unsigned char *)PyBytes_AS_STRING(result);
    Py_ssize_t pos = 0;

    for (Py_ssize_t idx = 0; idx < count; idx++) {
        PyObject *chunk = PyList_GET_ITEM(list, idx);
        long op = PyLong_AsLong(PyTuple_GET_ITEM(chunk, 0));
        PyObject *data = PyTuple_GET_ITEM(chunk, 1);

        out[pos++] = (unsigned char)op;
        if (data != Py_None) {
            Py_ssize_t dlen = PyBytes_GET_SIZE(data);
            const unsigned char *dbuf = (const unsigned char *)PyBytes_AS_STRING(data);
            if (op <= 75) {
                if (dlen != op) {
                    Py_DECREF(result);
                    PyErr_Format(PyExc_ValueError,
                        "Direct push opcode %ld requires data length %ld, got %zd",
                        op, op, dlen);
                    return NULL;
                }
            } else if (op == 0x4C) {
                if (dlen > 255) {
                    Py_DECREF(result);
                    PyErr_Format(PyExc_ValueError,
                        "OP_PUSHDATA1 data too long: %zd bytes", dlen);
                    return NULL;
                }
                out[pos++] = (unsigned char)dlen;
            } else if (op == 0x4D) {
                if (dlen > 65535) {
                    Py_DECREF(result);
                    PyErr_Format(PyExc_ValueError,
                        "OP_PUSHDATA2 data too long: %zd bytes", dlen);
                    return NULL;
                }
                out[pos++] = (unsigned char)(dlen & 0xFF);
                out[pos++] = (unsigned char)((dlen >> 8) & 0xFF);
            } else if (op == 0x4E) {
                if (dlen > 4294967295UL) {
                    Py_DECREF(result);
                    PyErr_Format(PyExc_ValueError,
                        "OP_PUSHDATA4 data too long: %zd bytes", dlen);
                    return NULL;
                }
                out[pos++] = (unsigned char)(dlen & 0xFF);
                out[pos++] = (unsigned char)((dlen >> 8) & 0xFF);
                out[pos++] = (unsigned char)((dlen >> 16) & 0xFF);
                out[pos++] = (unsigned char)((dlen >> 24) & 0xFF);
            } else {
                Py_DECREF(result);
                PyErr_Format(PyExc_ValueError,
                    "Non-push opcode %ld should not have data", op);
                return NULL;
            }
            memcpy(out + pos, dbuf, dlen);
            pos += dlen;
        }
    }

    return result;
}

/* ========================= Phase 1: Merkle =============================== */

/* Internal: double-SHA256 of exactly 64 bytes (two 32-byte hashes concatenated) */
static void hash256_64(const unsigned char *in, unsigned char *out) {
    unsigned char mid[32];
    secp256k1_sha256 h;
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(&h, in, 64);
    secp256k1_sha256_finalize(&h, mid);
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(&h, mid, 32);
    secp256k1_sha256_finalize(&h, out);
}

static void hash256_var(const unsigned char *in, size_t len, unsigned char *out) {
    unsigned char mid[32];
    secp256k1_sha256 h;
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(&h, in, len);
    secp256k1_sha256_finalize(&h, mid);
    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(&h, mid, 32);
    secp256k1_sha256_finalize(&h, out);
}

/*
 * merkle_compute_root(txid_hex, path) -> str
 *
 * path: list of levels, each level is list of dict with keys:
 *   "offset": int, "hash_str": str (hex, optional), "duplicate": bool (optional)
 *
 * Mirrors MerklePath.compute_root() but does all hashing in C.
 */
static PyObject* pyfn_merkle_compute_root(PyObject *self, PyObject *args) {
    const char *txid_hex;
    PyObject *path_list;
    if (!PyArg_ParseTuple(args, "sO", &txid_hex, &path_list))
        return NULL;

    if (!PyList_Check(path_list)) {
        PyErr_SetString(PyExc_TypeError, "path must be a list of levels");
        return NULL;
    }

    Py_ssize_t path_len = PyList_Size(path_list);
    if (path_len == 0) {
        return PyUnicode_FromString(txid_hex);
    }

    /* Parse txid hex to bytes (reversed - internal byte order) */
    unsigned char working[32];
    size_t txid_slen = strlen(txid_hex);
    if (txid_slen != 64) {
        PyErr_SetString(PyExc_ValueError, "txid must be 64 hex chars");
        return NULL;
    }
    if (hex_to_bytes_reversed(txid_hex, working, 32) < 0) {
        PyErr_SetString(PyExc_ValueError, "invalid hex in txid");
        return NULL;
    }

    /* Find the index of the txid at level 0 */
    PyObject *level0 = PyList_GET_ITEM(path_list, 0);
    if (!PyList_Check(level0)) {
        PyErr_SetString(PyExc_TypeError, "each level must be a list");
        return NULL;
    }

    long index = -1;
    Py_ssize_t level0_len = PyList_Size(level0);
    for (Py_ssize_t li = 0; li < level0_len; li++) {
        PyObject *leaf = PyList_GET_ITEM(level0, li);
        PyObject *hash_obj = PyDict_GetItemString(leaf, "hash_str");
        if (hash_obj && PyUnicode_Check(hash_obj)) {
            const char *leaf_hex = PyUnicode_AsUTF8(hash_obj);
            if (leaf_hex && strcmp(leaf_hex, txid_hex) == 0) {
                PyObject *off_obj = PyDict_GetItemString(leaf, "offset");
                if (off_obj) index = PyLong_AsLong(off_obj);
                break;
            }
        }
    }
    if (index < 0) {
        PyErr_Format(PyExc_ValueError, "txid not found in path level 0");
        return NULL;
    }

    /* Walk up the tree */
    for (Py_ssize_t height = 0; height < path_len; height++) {
        long offset = (index >> height) ^ 1;

        PyObject *level = PyList_GET_ITEM(path_list, height);
        if (!PyList_Check(level)) {
            PyErr_SetString(PyExc_TypeError, "each level must be a list");
            return NULL;
        }

        /* Find leaf at this offset */
        PyObject *leaf = NULL;
        Py_ssize_t lev_len = PyList_Size(level);
        for (Py_ssize_t li = 0; li < lev_len; li++) {
            PyObject *candidate = PyList_GET_ITEM(level, li);
            PyObject *off_obj = PyDict_GetItemString(candidate, "offset");
            if (off_obj && PyLong_AsLong(off_obj) == offset) {
                leaf = candidate;
                break;
            }
        }

        if (!leaf) {
            PyErr_Format(PyExc_ValueError,
                "Missing hash for index %ld at height %zd", index, height);
            return NULL;
        }

        /* Check duplicate flag */
        PyObject *dup_obj = PyDict_GetItemString(leaf, "duplicate");
        int is_dup = dup_obj && PyObject_IsTrue(dup_obj);

        unsigned char pair[32];
        if (is_dup) {
            memcpy(pair, working, 32);
        } else {
            /* Parse hex hash of the pair node */
            PyObject *hash_obj = PyDict_GetItemString(leaf, "hash_str");
            if (!hash_obj || !PyUnicode_Check(hash_obj)) {
                PyErr_SetString(PyExc_ValueError, "leaf missing hash_str");
                return NULL;
            }
            const char *pair_hex = PyUnicode_AsUTF8(hash_obj);
            if (!pair_hex || strlen(pair_hex) != 64) {
                PyErr_SetString(PyExc_ValueError, "invalid hash_str length");
                return NULL;
            }
            if (hex_to_bytes_reversed(pair_hex, pair, 32) < 0) {
                PyErr_SetString(PyExc_ValueError, "invalid hex in hash_str");
                return NULL;
            }
        }

        /* Concatenate and hash.
         * Python: hash256(to_bytes(left_hex + right_hex)[::-1])
         * Full 64-byte reversal swaps the two halves, so display-order
         * left||right becomes internal-order right_rev||left_rev. */
        unsigned char concat[64];
        if (is_dup) {
            memcpy(concat, working, 32);
            memcpy(concat + 32, working, 32);
        } else if (offset % 2 != 0) {
            memcpy(concat, working, 32);
            memcpy(concat + 32, pair, 32);
        } else {
            memcpy(concat, pair, 32);
            memcpy(concat + 32, working, 32);
        }

        hash256_64(concat, working);
    }

    /* Convert working hash back to display hex (reversed) */
    char result_hex[65];
    bytes_to_hex_reversed(working, result_hex, 32);
    result_hex[64] = '\0';
    return PyUnicode_FromString(result_hex);
}

/*
 * merkle_hash_pair(left_hex, right_hex) -> str
 *
 * Mirrors Python: to_hex(hash256(to_bytes(left+right, "hex")[::-1])[::-1])
 * Concatenates two 64-char hex strings, converts the 128-char hex to 64 bytes,
 * reverses the entire 64 bytes, applies hash256, reverses the 32-byte result.
 */
static PyObject* pyfn_merkle_hash_pair(PyObject *self, PyObject *args) {
    const char *left_hex, *right_hex;
    if (!PyArg_ParseTuple(args, "ss", &left_hex, &right_hex))
        return NULL;

    if (strlen(left_hex) != 64 || strlen(right_hex) != 64) {
        PyErr_SetString(PyExc_ValueError, "hex strings must be 64 chars");
        return NULL;
    }

    /* Parse 128-char hex (left+right) into 64 bytes */
    unsigned char combined[64];
    if (hex_to_bytes(left_hex, combined, 32) < 0) {
        PyErr_SetString(PyExc_ValueError, "invalid left hex");
        return NULL;
    }
    if (hex_to_bytes(right_hex, combined + 32, 32) < 0) {
        PyErr_SetString(PyExc_ValueError, "invalid right hex");
        return NULL;
    }

    /* Reverse entire 64 bytes */
    for (int i = 0; i < 32; i++) {
        unsigned char tmp = combined[i];
        combined[i] = combined[63 - i];
        combined[63 - i] = tmp;
    }

    /* hash256 */
    unsigned char out[32];
    hash256_64(combined, out);

    /* Reverse 32-byte result, then hex-encode */
    char result_hex[65];
    bytes_to_hex_reversed(out, result_hex, 32);
    result_hex[64] = '\0';
    return PyUnicode_FromString(result_hex);
}

/* ========================= Phase 1: Tx parse/serialize =================== */

/* Internal: read varint from buffer, return -1 on error */
static int64_t read_varint(const unsigned char *data, Py_ssize_t len,
                            Py_ssize_t *pos) {
    if (*pos >= len) return -1;
    unsigned char first = data[*pos];
    (*pos)++;
    if (first < 0xFD) return first;
    if (first == 0xFD) {
        if (*pos + 2 > len) return -1;
        uint16_t v = data[*pos] | ((uint16_t)data[*pos+1] << 8);
        *pos += 2;
        return v;
    }
    if (first == 0xFE) {
        if (*pos + 4 > len) return -1;
        uint32_t v = data[*pos] | ((uint32_t)data[*pos+1] << 8) |
                     ((uint32_t)data[*pos+2] << 16) | ((uint32_t)data[*pos+3] << 24);
        *pos += 4;
        return v;
    }
    /* 0xFF: 8-byte */
    if (*pos + 8 > len) return -1;
    uint64_t v = 0;
    for (int k = 0; k < 8; k++)
        v |= ((uint64_t)data[*pos + k]) << (k * 8);
    *pos += 8;
    return (int64_t)v;
}

/* Internal: write varint to buffer, return bytes written */
static int write_varint(unsigned char *out, uint64_t n) {
    if (n < 0xFD) {
        out[0] = (unsigned char)n;
        return 1;
    }
    if (n <= 0xFFFF) {
        out[0] = 0xFD;
        out[1] = (unsigned char)(n & 0xFF);
        out[2] = (unsigned char)((n >> 8) & 0xFF);
        return 3;
    }
    if (n <= 0xFFFFFFFF) {
        out[0] = 0xFE;
        out[1] = (unsigned char)(n & 0xFF);
        out[2] = (unsigned char)((n >> 8) & 0xFF);
        out[3] = (unsigned char)((n >> 16) & 0xFF);
        out[4] = (unsigned char)((n >> 24) & 0xFF);
        return 5;
    }
    out[0] = 0xFF;
    for (int k = 0; k < 8; k++)
        out[k+1] = (unsigned char)((n >> (k * 8)) & 0xFF);
    return 9;
}

/* Internal: varint encoded size */
static int varint_size(uint64_t n) {
    if (n < 0xFD) return 1;
    if (n <= 0xFFFF) return 3;
    if (n <= 0xFFFFFFFF) return 5;
    return 9;
}

/*
 * tx_from_bytes(raw_bytes) -> dict
 *
 * Returns dict with keys:
 *   "version": int,
 *   "locktime": int,
 *   "inputs": list of dict(source_txid=str, source_output_index=int,
 *                           unlocking_script=bytes, sequence=int),
 *   "outputs": list of dict(satoshis=int, locking_script=bytes),
 *   "bytes_read": int  (how many bytes consumed, for BEEF parsing)
 */
static PyObject* pyfn_tx_from_bytes(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    const unsigned char *data = (const unsigned char *)buf.buf;
    Py_ssize_t len = buf.len;
    Py_ssize_t pos = 0;

    /* Version (4 bytes LE) */
    if (pos + 4 > len) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "incomplete data: cannot read version");
        return NULL;
    }
    uint32_t version = data[pos] | ((uint32_t)data[pos+1] << 8) |
                       ((uint32_t)data[pos+2] << 16) | ((uint32_t)data[pos+3] << 24);
    pos += 4;

    /* Inputs count */
    int64_t n_inputs = read_varint(data, len, &pos);
    if (n_inputs < 0) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "incomplete data: cannot read inputs count");
        return NULL;
    }

    PyObject *inputs = PyList_New(0);
    if (!inputs) { PyBuffer_Release(&buf); return NULL; }

    for (int64_t i = 0; i < n_inputs; i++) {
        /* txid (32 bytes, reversed for display) */
        if (pos + 32 > len) goto parse_err;
        char txid_hex[65];
        bytes_to_hex_reversed(data + pos, txid_hex, 32);
        txid_hex[64] = '\0';
        pos += 32;

        /* vout (4 bytes LE) */
        if (pos + 4 > len) goto parse_err;
        uint32_t vout = data[pos] | ((uint32_t)data[pos+1] << 8) |
                        ((uint32_t)data[pos+2] << 16) | ((uint32_t)data[pos+3] << 24);
        pos += 4;

        /* script length + script */
        int64_t script_len = read_varint(data, len, &pos);
        if (script_len < 0 || pos + script_len > len) goto parse_err;
        PyObject *script = PyBytes_FromStringAndSize((const char *)(data + pos), script_len);
        pos += script_len;

        /* sequence (4 bytes LE) */
        if (pos + 4 > len) { Py_DECREF(script); goto parse_err; }
        uint32_t seq = data[pos] | ((uint32_t)data[pos+1] << 8) |
                       ((uint32_t)data[pos+2] << 16) | ((uint32_t)data[pos+3] << 24);
        pos += 4;

        PyObject *inp = PyDict_New();
        PyDict_SetItemString(inp, "source_txid", PyUnicode_FromString(txid_hex));
        PyDict_SetItemString(inp, "source_output_index", PyLong_FromUnsignedLong(vout));
        PyDict_SetItemString(inp, "unlocking_script", script);
        PyDict_SetItemString(inp, "sequence", PyLong_FromUnsignedLong(seq));
        Py_DECREF(script);

        PyList_Append(inputs, inp);
        Py_DECREF(inp);
    }

    /* Outputs count */
    int64_t n_outputs = read_varint(data, len, &pos);
    if (n_outputs < 0) goto parse_err;

    PyObject *outputs = PyList_New(0);
    if (!outputs) goto parse_err;

    for (int64_t i = 0; i < n_outputs; i++) {
        /* satoshis (8 bytes LE) */
        if (pos + 8 > len) { Py_DECREF(outputs); goto parse_err; }
        uint64_t sats = 0;
        for (int k = 0; k < 8; k++)
            sats |= ((uint64_t)data[pos + k]) << (k * 8);
        pos += 8;

        /* script length + script */
        int64_t script_len = read_varint(data, len, &pos);
        if (script_len < 0 || pos + script_len > len) { Py_DECREF(outputs); goto parse_err; }
        PyObject *script = PyBytes_FromStringAndSize((const char *)(data + pos), script_len);
        pos += script_len;

        PyObject *outp = PyDict_New();
        PyDict_SetItemString(outp, "satoshis", PyLong_FromUnsignedLongLong(sats));
        PyDict_SetItemString(outp, "locking_script", script);
        Py_DECREF(script);

        PyList_Append(outputs, outp);
        Py_DECREF(outp);
    }

    /* Locktime (4 bytes LE) */
    if (pos + 4 > len) { Py_DECREF(outputs); goto parse_err; }
    uint32_t locktime = data[pos] | ((uint32_t)data[pos+1] << 8) |
                        ((uint32_t)data[pos+2] << 16) | ((uint32_t)data[pos+3] << 24);
    pos += 4;

    /* Build result dict */
    PyObject *result = PyDict_New();
    PyDict_SetItemString(result, "version", PyLong_FromUnsignedLong(version));
    PyDict_SetItemString(result, "locktime", PyLong_FromUnsignedLong(locktime));
    PyDict_SetItemString(result, "inputs", inputs);
    PyDict_SetItemString(result, "outputs", outputs);
    PyDict_SetItemString(result, "bytes_read", PyLong_FromSsize_t(pos));
    Py_DECREF(inputs);
    Py_DECREF(outputs);

    PyBuffer_Release(&buf);
    return result;

parse_err:
    Py_DECREF(inputs);
    PyBuffer_Release(&buf);
    PyErr_SetString(PyExc_ValueError, "incomplete or invalid transaction data");
    return NULL;
}

/*
 * tx_to_bytes(version, inputs, outputs, locktime) -> bytes
 *
 * inputs: list of dict(source_txid=str, unlocking_script=bytes,
 *                       source_output_index=int, sequence=int)
 * outputs: list of dict(satoshis=int, locking_script=bytes)
 */
static PyObject* pyfn_tx_to_bytes(PyObject *self, PyObject *args) {
    unsigned int version, locktime;
    PyObject *inputs, *outputs;
    if (!PyArg_ParseTuple(args, "IOOI", &version, &inputs, &outputs, &locktime))
        return NULL;

    if (!PyList_Check(inputs) || !PyList_Check(outputs)) {
        PyErr_SetString(PyExc_TypeError, "inputs and outputs must be lists");
        return NULL;
    }

    Py_ssize_t n_in = PyList_Size(inputs);
    Py_ssize_t n_out = PyList_Size(outputs);

    /* Calculate total size */
    Py_ssize_t total = 4; /* version */
    total += varint_size(n_in);
    for (Py_ssize_t i = 0; i < n_in; i++) {
        PyObject *inp = PyList_GET_ITEM(inputs, i);
        PyObject *script = PyDict_GetItemString(inp, "unlocking_script");
        Py_ssize_t slen = script && PyBytes_Check(script) ? PyBytes_GET_SIZE(script) : 0;
        total += 32 + 4 + varint_size(slen) + slen + 4; /* txid + vout + script + seq */
    }
    total += varint_size(n_out);
    for (Py_ssize_t i = 0; i < n_out; i++) {
        PyObject *outp = PyList_GET_ITEM(outputs, i);
        PyObject *script = PyDict_GetItemString(outp, "locking_script");
        Py_ssize_t slen = script && PyBytes_Check(script) ? PyBytes_GET_SIZE(script) : 0;
        total += 8 + varint_size(slen) + slen; /* satoshis + script */
    }
    total += 4; /* locktime */

    PyObject *result = PyBytes_FromStringAndSize(NULL, total);
    if (!result) return NULL;
    unsigned char *out = (unsigned char *)PyBytes_AS_STRING(result);
    Py_ssize_t pos = 0;

    /* Version */
    out[pos++] = (unsigned char)(version & 0xFF);
    out[pos++] = (unsigned char)((version >> 8) & 0xFF);
    out[pos++] = (unsigned char)((version >> 16) & 0xFF);
    out[pos++] = (unsigned char)((version >> 24) & 0xFF);

    /* Inputs */
    pos += write_varint(out + pos, n_in);
    for (Py_ssize_t i = 0; i < n_in; i++) {
        PyObject *inp = PyList_GET_ITEM(inputs, i);

        /* txid hex -> bytes reversed */
        PyObject *txid_obj = PyDict_GetItemString(inp, "source_txid");
        const char *txid_hex = PyUnicode_AsUTF8(txid_obj);
        hex_to_bytes_reversed(txid_hex, out + pos, 32);
        pos += 32;

        /* vout */
        PyObject *vout_obj = PyDict_GetItemString(inp, "source_output_index");
        uint32_t vout = (uint32_t)PyLong_AsUnsignedLong(vout_obj);
        out[pos++] = (unsigned char)(vout & 0xFF);
        out[pos++] = (unsigned char)((vout >> 8) & 0xFF);
        out[pos++] = (unsigned char)((vout >> 16) & 0xFF);
        out[pos++] = (unsigned char)((vout >> 24) & 0xFF);

        /* unlocking script */
        PyObject *script = PyDict_GetItemString(inp, "unlocking_script");
        Py_ssize_t slen = script && PyBytes_Check(script) ? PyBytes_GET_SIZE(script) : 0;
        pos += write_varint(out + pos, slen);
        if (slen > 0) {
            memcpy(out + pos, PyBytes_AS_STRING(script), slen);
            pos += slen;
        }

        /* sequence */
        PyObject *seq_obj = PyDict_GetItemString(inp, "sequence");
        uint32_t seq = (uint32_t)PyLong_AsUnsignedLong(seq_obj);
        out[pos++] = (unsigned char)(seq & 0xFF);
        out[pos++] = (unsigned char)((seq >> 8) & 0xFF);
        out[pos++] = (unsigned char)((seq >> 16) & 0xFF);
        out[pos++] = (unsigned char)((seq >> 24) & 0xFF);
    }

    /* Outputs */
    pos += write_varint(out + pos, n_out);
    for (Py_ssize_t i = 0; i < n_out; i++) {
        PyObject *outp = PyList_GET_ITEM(outputs, i);

        /* satoshis */
        PyObject *sats_obj = PyDict_GetItemString(outp, "satoshis");
        uint64_t sats = PyLong_AsUnsignedLongLong(sats_obj);
        for (int k = 0; k < 8; k++)
            out[pos++] = (unsigned char)((sats >> (k * 8)) & 0xFF);

        /* locking script */
        PyObject *script = PyDict_GetItemString(outp, "locking_script");
        Py_ssize_t slen = script && PyBytes_Check(script) ? PyBytes_GET_SIZE(script) : 0;
        pos += write_varint(out + pos, slen);
        if (slen > 0) {
            memcpy(out + pos, PyBytes_AS_STRING(script), slen);
            pos += slen;
        }
    }

    /* Locktime */
    out[pos++] = (unsigned char)(locktime & 0xFF);
    out[pos++] = (unsigned char)((locktime >> 8) & 0xFF);
    out[pos++] = (unsigned char)((locktime >> 16) & 0xFF);
    out[pos++] = (unsigned char)((locktime >> 24) & 0xFF);

    return result;
}

/*
 * tx_txid(raw_bytes) -> str
 *
 * Compute txid directly from raw tx bytes: hash256(raw) reversed to hex.
 * Avoids round-trip through Python objects.
 */
static PyObject* pyfn_tx_txid(PyObject *self, PyObject *args) {
    Py_buffer buf;
    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;

    unsigned char mid[32], out[32];
    secp256k1_sha256 h;

    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(&h, (const unsigned char *)buf.buf, buf.len);
    secp256k1_sha256_finalize(&h, mid);

    secp256k1_sha256_initialize(&h);
    secp256k1_sha256_write(&h, mid, 32);
    secp256k1_sha256_finalize(&h, out);

    PyBuffer_Release(&buf);

    /* Reverse and hex-encode */
    char hex[65];
    bytes_to_hex_reversed(out, hex, 32);
    hex[64] = '\0';
    return PyUnicode_FromString(hex);
}

/* ========================= Phase 2: Preimage ============================= */

/*
 * Helper: extract input tuple fields.
 * tuple = (txid_hex, vout, locking_script_bytes, satoshis, sequence, sighash)
 * Returns 0 on success, -1 on error (with Python exception set).
 */
static int parse_input_tuple(PyObject *tup,
    const char **txid_hex, uint32_t *vout,
    const unsigned char **script, Py_ssize_t *script_len,
    int64_t *satoshis, uint32_t *sequence, uint32_t *sighash)
{
    PyObject *o_txid, *o_vout, *o_script, *o_sats, *o_seq, *o_sh;
    if (!PyTuple_Check(tup) || PyTuple_GET_SIZE(tup) != 6) {
        PyErr_SetString(PyExc_TypeError, "input must be (txid, vout, script, satoshis, sequence, sighash)");
        return -1;
    }
    o_txid   = PyTuple_GET_ITEM(tup, 0);
    o_vout   = PyTuple_GET_ITEM(tup, 1);
    o_script = PyTuple_GET_ITEM(tup, 2);
    o_sats   = PyTuple_GET_ITEM(tup, 3);
    o_seq    = PyTuple_GET_ITEM(tup, 4);
    o_sh     = PyTuple_GET_ITEM(tup, 5);

    if (!PyUnicode_Check(o_txid)) {
        PyErr_SetString(PyExc_TypeError, "txid must be str");
        return -1;
    }
    *txid_hex = PyUnicode_AsUTF8(o_txid);
    if (!*txid_hex || strlen(*txid_hex) != 64) {
        PyErr_SetString(PyExc_ValueError, "txid must be 64 hex chars");
        return -1;
    }
    *vout = (uint32_t)PyLong_AsUnsignedLong(o_vout);
    if (PyErr_Occurred()) return -1;
    if (!PyBytes_Check(o_script)) {
        PyErr_SetString(PyExc_TypeError, "locking_script must be bytes");
        return -1;
    }
    *script = (const unsigned char *)PyBytes_AS_STRING(o_script);
    *script_len = PyBytes_GET_SIZE(o_script);
    *satoshis = PyLong_AsLongLong(o_sats);
    if (PyErr_Occurred()) return -1;
    *sequence = (uint32_t)PyLong_AsUnsignedLong(o_seq);
    if (PyErr_Occurred()) return -1;
    *sighash = (uint32_t)PyLong_AsUnsignedLong(o_sh);
    if (PyErr_Occurred()) return -1;
    return 0;
}

/* Helper: write uint32 LE to buffer */
static void write_u32_le(unsigned char *buf, uint32_t v) {
    buf[0] = (unsigned char)(v & 0xFF);
    buf[1] = (unsigned char)((v >> 8) & 0xFF);
    buf[2] = (unsigned char)((v >> 16) & 0xFF);
    buf[3] = (unsigned char)((v >> 24) & 0xFF);
}

/* Helper: write uint64 LE to buffer */
static void write_u64_le(unsigned char *buf, uint64_t v) {
    for (int i = 0; i < 8; i++)
        buf[i] = (unsigned char)((v >> (i * 8)) & 0xFF);
}

/*
 * tx_preimages(version, locktime, inputs, outputs) -> list[bytes]
 *
 * Compute BIP-143 preimages for all inputs.
 * inputs: list of (txid_hex, vout, locking_script_bytes, satoshis, sequence, sighash)
 * outputs: list of bytes (pre-serialized)
 */
static PyObject* pyfn_tx_preimages(PyObject *self, PyObject *args) {
    uint32_t version, locktime;
    PyObject *inputs_list, *outputs_list;
    if (!PyArg_ParseTuple(args, "IIOO", &version, &locktime, &inputs_list, &outputs_list))
        return NULL;

    if (!PyList_Check(inputs_list) || !PyList_Check(outputs_list)) {
        PyErr_SetString(PyExc_TypeError, "inputs and outputs must be lists");
        return NULL;
    }

    Py_ssize_t n_in = PyList_GET_SIZE(inputs_list);
    Py_ssize_t n_out = PyList_GET_SIZE(outputs_list);

    /* --- Compute shared hashes: hashPrevouts, hashSequence, hashOutputs --- */

    /* hashPrevouts: hash256(txid_le(32) + vout_le(4) for each input) */
    size_t prevouts_len = (size_t)n_in * 36;
    unsigned char *prevouts_buf = (unsigned char *)malloc(prevouts_len > 0 ? prevouts_len : 1);
    if (!prevouts_buf) return PyErr_NoMemory();

    /* hashSequence: hash256(sequence_le(4) for each input) */
    size_t seq_len = (size_t)n_in * 4;
    unsigned char *seq_buf = (unsigned char *)malloc(seq_len > 0 ? seq_len : 1);
    if (!seq_buf) { free(prevouts_buf); return PyErr_NoMemory(); }

    /* Pre-parse all inputs */
    typedef struct {
        unsigned char txid_le[32];
        uint32_t vout;
        const unsigned char *script;
        Py_ssize_t script_len;
        int64_t satoshis;
        uint32_t sequence;
        uint32_t sighash;
    } InputInfo;

    InputInfo *infos = (InputInfo *)calloc(n_in > 0 ? n_in : 1, sizeof(InputInfo));
    if (!infos) { free(prevouts_buf); free(seq_buf); return PyErr_NoMemory(); }

    for (Py_ssize_t i = 0; i < n_in; i++) {
        const char *txid_hex;
        uint32_t vout, seq, sh;
        int64_t sats;
        const unsigned char *scr;
        Py_ssize_t scr_len;
        if (parse_input_tuple(PyList_GET_ITEM(inputs_list, i),
                &txid_hex, &vout, &scr, &scr_len, &sats, &seq, &sh) < 0) {
            free(prevouts_buf); free(seq_buf); free(infos);
            return NULL;
        }
        /* Convert txid hex to bytes reversed (display hex → internal LE) */
        if (hex_to_bytes_reversed(txid_hex, infos[i].txid_le, 32) < 0) {
            free(prevouts_buf); free(seq_buf); free(infos);
            PyErr_SetString(PyExc_ValueError, "invalid txid hex");
            return NULL;
        }
        infos[i].vout = vout;
        infos[i].script = scr;
        infos[i].script_len = scr_len;
        infos[i].satoshis = sats;
        infos[i].sequence = seq;
        infos[i].sighash = sh;

        /* Fill prevouts_buf */
        memcpy(prevouts_buf + i * 36, infos[i].txid_le, 32);
        write_u32_le(prevouts_buf + i * 36 + 32, vout);
        /* Fill seq_buf */
        write_u32_le(seq_buf + i * 4, seq);
    }

    unsigned char shared_hash_prevouts[32], shared_hash_sequence[32], shared_hash_outputs[32];
    hash256_var(prevouts_buf, prevouts_len, shared_hash_prevouts);
    hash256_var(seq_buf, seq_len, shared_hash_sequence);
    free(prevouts_buf);
    free(seq_buf);

    /* hashOutputs: hash256(all serialized outputs) */
    size_t total_out_len = 0;
    for (Py_ssize_t i = 0; i < n_out; i++) {
        PyObject *ob = PyList_GET_ITEM(outputs_list, i);
        if (!PyBytes_Check(ob)) {
            free(infos);
            PyErr_SetString(PyExc_TypeError, "output must be bytes");
            return NULL;
        }
        total_out_len += PyBytes_GET_SIZE(ob);
    }
    unsigned char *out_buf = (unsigned char *)malloc(total_out_len > 0 ? total_out_len : 1);
    if (!out_buf) { free(infos); return PyErr_NoMemory(); }
    size_t opos = 0;
    for (Py_ssize_t i = 0; i < n_out; i++) {
        PyObject *ob = PyList_GET_ITEM(outputs_list, i);
        Py_ssize_t olen = PyBytes_GET_SIZE(ob);
        memcpy(out_buf + opos, PyBytes_AS_STRING(ob), olen);
        opos += olen;
    }
    hash256_var(out_buf, total_out_len, shared_hash_outputs);
    free(out_buf);

    /* --- Build preimage for each input --- */
    static const unsigned char zeroes32[32] = {0};

    PyObject *result = PyList_New(n_in);
    if (!result) { free(infos); return NULL; }

    for (Py_ssize_t i = 0; i < n_in; i++) {
        InputInfo *inf = &infos[i];
        uint32_t sh = inf->sighash;
        uint32_t base = sh & 0x1F;

        const unsigned char *hp, *hs, *ho;

        /* hashPrevouts */
        hp = (sh & 0x80) ? zeroes32 : shared_hash_prevouts;

        /* hashSequence */
        if ((sh & 0x80) || base == 0x02 || base == 0x03)
            hs = zeroes32;
        else
            hs = shared_hash_sequence;

        /* hashOutputs */
        unsigned char single_hash_outputs[32];
        if (base != 0x03 && base != 0x02) {
            ho = shared_hash_outputs;
        } else if (base == 0x03 && i < n_out) {
            PyObject *ob = PyList_GET_ITEM(outputs_list, i);
            hash256_var((const unsigned char *)PyBytes_AS_STRING(ob),
                        PyBytes_GET_SIZE(ob), single_hash_outputs);
            ho = single_hash_outputs;
        } else {
            ho = zeroes32;
        }

        /* Build BIP-143 preimage:
         * version(4) + hashPrevouts(32) + hashSequence(32) + outpoint(36)
         * + varint+scriptCode + value(8) + sequence(4) + hashOutputs(32)
         * + locktime(4) + sighash(4) */
        int vi_len = varint_size(inf->script_len);
        size_t pre_len = 4 + 32 + 32 + 36 + vi_len + inf->script_len + 8 + 4 + 32 + 4 + 4;
        unsigned char *pre = (unsigned char *)malloc(pre_len);
        if (!pre) { free(infos); Py_DECREF(result); return PyErr_NoMemory(); }

        size_t p = 0;
        /* 1. version */
        write_u32_le(pre + p, version); p += 4;
        /* 2. hashPrevouts */
        memcpy(pre + p, hp, 32); p += 32;
        /* 3. hashSequence */
        memcpy(pre + p, hs, 32); p += 32;
        /* 4. outpoint (txid LE + vout LE) */
        memcpy(pre + p, inf->txid_le, 32); p += 32;
        write_u32_le(pre + p, inf->vout); p += 4;
        /* 5. scriptCode (varint len + bytes) */
        p += write_varint(pre + p, inf->script_len);
        memcpy(pre + p, inf->script, inf->script_len); p += inf->script_len;
        /* 6. value (8 bytes LE) */
        write_u64_le(pre + p, (uint64_t)inf->satoshis); p += 8;
        /* 7. nSequence */
        write_u32_le(pre + p, inf->sequence); p += 4;
        /* 8. hashOutputs */
        memcpy(pre + p, ho, 32); p += 32;
        /* 9. nLocktime */
        write_u32_le(pre + p, locktime); p += 4;
        /* 10. sighash */
        write_u32_le(pre + p, sh); p += 4;

        PyObject *preimage = PyBytes_FromStringAndSize((const char *)pre, (Py_ssize_t)p);
        free(pre);
        if (!preimage) { free(infos); Py_DECREF(result); return NULL; }
        PyList_SET_ITEM(result, i, preimage);
    }

    free(infos);
    return result;
}

/*
 * tx_preimage_otda(input_index, version, locktime, inputs, outputs) -> bytes
 *
 * Compute OTDA (Original Transaction Digest Algorithm) preimage.
 * inputs: list of (txid_hex, vout, locking_script_bytes, satoshis, sequence, sighash)
 * outputs: list of bytes (pre-serialized)
 */
static PyObject* pyfn_tx_preimage_otda(PyObject *self, PyObject *args) {
    int input_index;
    uint32_t version, locktime;
    PyObject *inputs_list, *outputs_list;
    if (!PyArg_ParseTuple(args, "iIIOO", &input_index, &version, &locktime,
                          &inputs_list, &outputs_list))
        return NULL;

    if (!PyList_Check(inputs_list) || !PyList_Check(outputs_list)) {
        PyErr_SetString(PyExc_TypeError, "inputs and outputs must be lists");
        return NULL;
    }

    Py_ssize_t n_in = PyList_GET_SIZE(inputs_list);
    Py_ssize_t n_out = PyList_GET_SIZE(outputs_list);

    if (input_index < 0 || input_index >= n_in) {
        PyErr_SetString(PyExc_IndexError, "input_index out of range");
        return NULL;
    }

    /* Parse signing input to get sighash */
    const char *sig_txid;
    uint32_t sig_vout, sig_seq, sig_sighash;
    int64_t sig_sats;
    const unsigned char *sig_script;
    Py_ssize_t sig_script_len;
    if (parse_input_tuple(PyList_GET_ITEM(inputs_list, input_index),
            &sig_txid, &sig_vout, &sig_script, &sig_script_len,
            &sig_sats, &sig_seq, &sig_sighash) < 0)
        return NULL;

    uint32_t base_type = sig_sighash & 0x1F;
    int anyonecanpay = sig_sighash & 0x80;

    /* Estimate buffer size (generous upper bound) */
    size_t est = 4; /* version */
    est += 9; /* varint input count */
    /* Per input: 32(txid) + 4(vout) + 9(varint) + script_len + 4(seq) */
    for (Py_ssize_t i = 0; i < n_in; i++) {
        PyObject *tup = PyList_GET_ITEM(inputs_list, i);
        if (PyTuple_Check(tup) && PyTuple_GET_SIZE(tup) >= 3) {
            PyObject *sc = PyTuple_GET_ITEM(tup, 2);
            if (PyBytes_Check(sc))
                est += 36 + 9 + PyBytes_GET_SIZE(sc) + 4;
            else
                est += 36 + 9 + 4;
        } else {
            est += 49;
        }
    }
    est += 9; /* varint output count */
    for (Py_ssize_t i = 0; i < n_out; i++) {
        PyObject *ob = PyList_GET_ITEM(outputs_list, i);
        if (PyBytes_Check(ob))
            est += PyBytes_GET_SIZE(ob);
        else
            est += 34;
    }
    est += 4 + 4; /* locktime + sighash */

    unsigned char *buf = (unsigned char *)malloc(est);
    if (!buf) return PyErr_NoMemory();
    size_t p = 0;

    /* nVersion */
    write_u32_le(buf + p, version); p += 4;

    /* Inputs */
    Py_ssize_t in_count = anyonecanpay ? 1 : n_in;
    p += write_varint(buf + p, in_count);

    for (Py_ssize_t i = 0; i < n_in; i++) {
        if (anyonecanpay && i != input_index) continue;

        const char *txid_hex;
        uint32_t vout, seq, sh;
        int64_t sats;
        const unsigned char *scr;
        Py_ssize_t scr_len;
        if (parse_input_tuple(PyList_GET_ITEM(inputs_list, i),
                &txid_hex, &vout, &scr, &scr_len, &sats, &seq, &sh) < 0) {
            free(buf);
            return NULL;
        }

        /* outpoint: txid reversed + vout */
        unsigned char txid_le[32];
        if (hex_to_bytes_reversed(txid_hex, txid_le, 32) < 0) {
            free(buf); PyErr_SetString(PyExc_ValueError, "invalid txid hex"); return NULL;
        }
        memcpy(buf + p, txid_le, 32); p += 32;
        write_u32_le(buf + p, vout); p += 4;

        /* scriptSig: only for signing input */
        if ((Py_ssize_t)i == input_index) {
            p += write_varint(buf + p, scr_len);
            memcpy(buf + p, scr, scr_len); p += scr_len;
        } else {
            buf[p++] = 0x00; /* varint(0) */
        }

        /* sequence: zero for other inputs with NONE/SINGLE */
        if ((Py_ssize_t)i != input_index &&
            (base_type == 0x02 || base_type == 0x03)) {
            write_u32_le(buf + p, 0); p += 4;
        } else {
            write_u32_le(buf + p, seq); p += 4;
        }
    }

    /* Outputs */
    if (base_type == 0x02) {
        /* SIGHASH_NONE: no outputs */
        buf[p++] = 0x00;
    } else if (base_type == 0x03) {
        /* SIGHASH_SINGLE: outputs up to input_index */
        Py_ssize_t out_count = input_index + 1;
        p += write_varint(buf + p, out_count);
        for (Py_ssize_t i = 0; i < out_count; i++) {
            if (i < input_index) {
                /* Null output: satoshis = 0xFFFFFFFFFFFFFFFF, empty script */
                write_u64_le(buf + p, 0xFFFFFFFFFFFFFFFFULL); p += 8;
                buf[p++] = 0x00;
            } else {
                PyObject *ob = PyList_GET_ITEM(outputs_list, i);
                if (!PyBytes_Check(ob)) {
                    free(buf);
                    PyErr_SetString(PyExc_TypeError, "output must be bytes");
                    return NULL;
                }
                Py_ssize_t olen = PyBytes_GET_SIZE(ob);
                memcpy(buf + p, PyBytes_AS_STRING(ob), olen); p += olen;
            }
        }
    } else {
        /* SIGHASH_ALL: all outputs */
        p += write_varint(buf + p, n_out);
        for (Py_ssize_t i = 0; i < n_out; i++) {
            PyObject *ob = PyList_GET_ITEM(outputs_list, i);
            if (!PyBytes_Check(ob)) {
                free(buf);
                PyErr_SetString(PyExc_TypeError, "output must be bytes");
                return NULL;
            }
            Py_ssize_t olen = PyBytes_GET_SIZE(ob);
            memcpy(buf + p, PyBytes_AS_STRING(ob), olen); p += olen;
        }
    }

    /* nLockTime */
    write_u32_le(buf + p, locktime); p += 4;

    /* sighash type */
    write_u32_le(buf + p, sig_sighash); p += 4;

    PyObject *result = PyBytes_FromStringAndSize((const char *)buf, (Py_ssize_t)p);
    free(buf);
    return result;
}

/* ========================= Phase 3: Script VM ============================== */

#define VM_MAX_ELEM_SIZE           (1024 * 1024 * 1024)
#define VM_STACK_INIT              64
#define VM_IFSTACK_INIT            16
#define VM_CTX_UNLOCK              0
#define VM_CTX_LOCK                1
#define VM_MAX_MULTISIG_KEY_COUNT  2147483647LL

typedef struct { unsigned char *data; Py_ssize_t len; } StackElem;
typedef struct { StackElem *items; Py_ssize_t count, capacity; } VmStack;
typedef struct { uint8_t *flags; Py_ssize_t count, capacity; } IfStack;

/* Phase 3c: preimage context for CHECKSIG C internalization */
typedef struct {
    unsigned char txid_le[32];
    uint32_t vout;
    const unsigned char *script;
    Py_ssize_t script_len;
    int64_t satoshis;
    uint32_t sequence;
    uint32_t sighash;
} PCtxInput;

typedef struct {
    uint32_t version;
    uint32_t locktime;
    int32_t  input_index;
    unsigned char cur_txid_le[32];
    uint32_t cur_vout;
    int64_t  cur_satoshis;
    uint32_t cur_sequence;
    PCtxInput *other_inputs;
    Py_ssize_t n_other;
    PyObject *outputs_list;
    Py_ssize_t n_outputs;
    unsigned char hash_prevouts[32];
    unsigned char hash_sequence[32];
    unsigned char hash_outputs[32];
} PreimageCtx;

typedef struct {
    VmStack     stack;
    VmStack     alt_stack;
    IfStack     if_stack;
    PyObject   *unlock_chunks;
    PyObject   *lock_chunks;
    Py_ssize_t  program_counter;
    int         context;
    Py_ssize_t  last_code_separator;
    int         tx_version;
    const char *source_txid;
    int         source_output_index;
    PreimageCtx pctx;
} VMState;

/* --- VmStack helpers ---------------------------------------------------- */

static void vms_init(VmStack *s) {
    s->items = NULL; s->count = 0; s->capacity = 0;
}
static int vms_ensure(VmStack *s, Py_ssize_t extra) {
    if (s->count + extra <= s->capacity) return 0;
    Py_ssize_t nc = s->capacity ? s->capacity * 2 : VM_STACK_INIT;
    while (nc < s->count + extra) nc *= 2;
    StackElem *ni = (StackElem *)PyMem_Realloc(s->items, nc * sizeof(StackElem));
    if (!ni) { PyErr_NoMemory(); return -1; }
    s->items = ni; s->capacity = nc;
    return 0;
}
static void se_free(StackElem *e) {
    if (e->data) { PyMem_Free(e->data); e->data = NULL; }
    e->len = 0;
}
static int vms_push(VmStack *s, const unsigned char *data, Py_ssize_t len) {
    if (vms_ensure(s, 1) < 0) return -1;
    StackElem *e = &s->items[s->count];
    if (len > 0 && data) {
        e->data = (unsigned char *)PyMem_Malloc(len);
        if (!e->data) { PyErr_NoMemory(); return -1; }
        memcpy(e->data, data, len);
    } else {
        e->data = NULL;
    }
    e->len = len;
    s->count++;
    return 0;
}
static int vms_push_take(VmStack *s, unsigned char *data, Py_ssize_t len) {
    if (vms_ensure(s, 1) < 0) return -1;
    s->items[s->count].data = data;
    s->items[s->count].len = len;
    s->count++;
    return 0;
}
static StackElem *vms_top(const VmStack *s, int off) {
    return &s->items[s->count + off];
}
static int vms_pop(VmStack *s, StackElem *out) {
    if (s->count < 1) return -1;
    s->count--;
    if (out) *out = s->items[s->count];
    else se_free(&s->items[s->count]);
    return 0;
}
static int vms_remove(VmStack *s, Py_ssize_t idx, StackElem *out) {
    if (idx < 0 || idx >= s->count) return -1;
    if (out) *out = s->items[idx];
    else se_free(&s->items[idx]);
    memmove(&s->items[idx], &s->items[idx + 1],
            (s->count - idx - 1) * sizeof(StackElem));
    s->count--;
    return 0;
}
static void vms_free(VmStack *s) {
    for (Py_ssize_t i = 0; i < s->count; i++) se_free(&s->items[i]);
    if (s->items) PyMem_Free(s->items);
    s->items = NULL; s->count = 0; s->capacity = 0;
}

/* --- IfStack helpers ---------------------------------------------------- */

static void ifs_init(IfStack *s) {
    s->flags = NULL; s->count = 0; s->capacity = 0;
}
static int ifs_push(IfStack *s, uint8_t val) {
    if (s->count >= s->capacity) {
        Py_ssize_t nc = s->capacity ? s->capacity * 2 : VM_IFSTACK_INIT;
        uint8_t *nf = (uint8_t *)PyMem_Realloc(s->flags, nc);
        if (!nf) { PyErr_NoMemory(); return -1; }
        s->flags = nf; s->capacity = nc;
    }
    s->flags[s->count++] = val;
    return 0;
}
static int ifs_all_true(const IfStack *s) {
    for (Py_ssize_t i = 0; i < s->count; i++)
        if (!s->flags[i]) return 0;
    return 1;
}
static void ifs_free(IfStack *s) {
    if (s->flags) PyMem_Free(s->flags);
    s->flags = NULL; s->count = 0; s->capacity = 0;
}

/* --- Script number helpers ---------------------------------------------- */

static PyObject *c_bin2num(const unsigned char *data, Py_ssize_t len) {
    if (len == 0) return PyLong_FromLong(0);
    int negative = data[len - 1] & 0x80;
    if (len <= 8) {
        uint64_t val = 0;
        for (Py_ssize_t i = len - 1; i >= 0; i--)
            val = (val << 8) | data[i];
        uint64_t mask = (uint64_t)0x80 << ((len - 1) * 8);
        val &= ~mask;
        if (negative) return PyLong_FromLongLong(-(long long)val);
        return PyLong_FromUnsignedLongLong(val);
    }
    unsigned char *tmp = (unsigned char *)PyMem_Malloc(len);
    if (!tmp) { PyErr_NoMemory(); return NULL; }
    memcpy(tmp, data, len);
    tmp[len - 1] &= 0x7F;
    PyObject *n = _PyLong_FromByteArray(tmp, (size_t)len, 1, 0);
    PyMem_Free(tmp);
    if (!n) return NULL;
    if (negative) {
        PyObject *neg = PyNumber_Negative(n);
        Py_DECREF(n);
        return neg;
    }
    return n;
}

static int c_min_encode(PyObject *num, unsigned char **out, Py_ssize_t *out_len) {
    int is_zero = PyObject_Not(num);
    if (is_zero < 0) return -1;
    if (is_zero) { *out = NULL; *out_len = 0; return 0; }

    PyObject *pz = PyLong_FromLong(0);
    int negative = PyObject_RichCompareBool(num, pz, Py_LT);
    Py_DECREF(pz);
    if (negative < 0) return -1;

    PyObject *abs_num = negative ? PyNumber_Negative(num) : num;
    if (!abs_num) return -1;
    if (!negative) Py_INCREF(abs_num);

    PyObject *bl = PyObject_CallMethod(abs_num, "bit_length", NULL);
    if (!bl) { Py_DECREF(abs_num); return -1; }
    long bits = PyLong_AsLong(bl);
    Py_DECREF(bl);

    Py_ssize_t nb = (bits + 7) / 8;
    if (nb == 0) nb = 1;

    unsigned char *buf = (unsigned char *)PyMem_Malloc(nb + 1);
    if (!buf) { Py_DECREF(abs_num); PyErr_NoMemory(); return -1; }

    if (_PyLong_AsByteArray((PyLongObject *)abs_num, buf, (size_t)nb, 1, 0) < 0) {
        PyMem_Free(buf); Py_DECREF(abs_num); return -1;
    }
    Py_DECREF(abs_num);

    if (buf[nb - 1] & 0x80) { buf[nb] = 0x00; nb++; }
    if (negative) buf[nb - 1] |= 0x80;
    *out = buf; *out_len = nb;
    return 0;
}

static int vms_push_num(VmStack *s, PyObject *num) {
    unsigned char *data; Py_ssize_t len;
    if (c_min_encode(num, &data, &len) < 0) return -1;
    int rc = vms_push_take(s, data, len);
    if (rc < 0 && data) PyMem_Free(data);
    return rc;
}

static PyObject *vms_pop_num(VmStack *s) {
    StackElem e;
    if (vms_pop(s, &e) < 0) return NULL;
    PyObject *n = c_bin2num(e.data, e.len);
    se_free(&e);
    return n;
}

static PyObject *vms_remove_num(VmStack *s, Py_ssize_t idx) {
    StackElem e;
    if (vms_remove(s, idx, &e) < 0) return NULL;
    PyObject *n = c_bin2num(e.data, e.len);
    se_free(&e);
    return n;
}

/* --- VM helpers --------------------------------------------------------- */

static int c_cast_to_bool(const unsigned char *data, Py_ssize_t len) {
    for (Py_ssize_t i = 0; i < len; i++) {
        if (data[i] != 0) {
            if (i == len - 1 && data[i] == 0x80) return 0;
            return 1;
        }
    }
    return 0;
}

static int c_is_chunk_minimal(int op, const unsigned char *data, Py_ssize_t dlen) {
    if (!data) return 1;
    if (dlen == 0) return (op == 0x00);
    if (dlen == 1 && data[0] >= 1 && data[0] <= 16)
        return (op == 0x51 + (data[0] - 1));
    if (dlen == 1 && data[0] == 0x81) return (op == 0x4F);
    if (dlen <= 75)    return (op == (int)dlen);
    if (dlen <= 255)   return (op == 0x4C);
    if (dlen <= 65535) return (op == 0x4D);
    return (op == 0x4E);
}

static void vm_error(VMState *st, const char *msg) {
    const char *ctx = st->context == VM_CTX_UNLOCK ? "UnlockingScript" : "LockingScript";
    PyErr_Format(PyExc_RuntimeError,
        "Script evaluation error: %s\n\n"
        "Source TXID: %s\n"
        "Source output index: %d\n"
        "Context: %s\n"
        "Program counter: %zd\n"
        "Stack size: %zd\n"
        "Alt stack size: %zd",
        msg, st->source_txid, st->source_output_index,
        ctx, st->program_counter, st->stack.count, st->alt_stack.count);
}

static void vm_errorf(VMState *st, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    vm_error(st, buf);
}

static const char *vm_opname(int op) {
    switch (op) {
    case 0x79: return "OP_PICK";
    case 0x7A: return "OP_ROLL";
    case 0x83: return "OP_INVERT";
    case 0x84: return "OP_AND";
    case 0x85: return "OP_OR";
    case 0x86: return "OP_XOR";
    case 0x87: return "OP_EQUAL";
    case 0x88: return "OP_EQUALVERIFY";
    case 0x8B: return "OP_1ADD";
    case 0x8C: return "OP_1SUB";
    case 0x8D: return "OP_2MUL";
    case 0x8E: return "OP_2DIV";
    case 0x8F: return "OP_NEGATE";
    case 0x90: return "OP_ABS";
    case 0x91: return "OP_NOT";
    case 0x92: return "OP_0NOTEQUAL";
    case 0x93: return "OP_ADD";
    case 0x94: return "OP_SUB";
    case 0x95: return "OP_MUL";
    case 0x96: return "OP_DIV";
    case 0x97: return "OP_MOD";
    case 0x98: return "OP_LSHIFT";
    case 0x99: return "OP_RSHIFT";
    case 0x9A: return "OP_BOOLAND";
    case 0x9B: return "OP_BOOLOR";
    case 0x9C: return "OP_NUMEQUAL";
    case 0x9D: return "OP_NUMEQUALVERIFY";
    case 0x9E: return "OP_NUMNOTEQUAL";
    case 0x9F: return "OP_LESSTHAN";
    case 0xA0: return "OP_GREATERTHAN";
    case 0xA1: return "OP_LESSTHANOREQUAL";
    case 0xA2: return "OP_GREATERTHANOREQUAL";
    case 0xA3: return "OP_MIN";
    case 0xA4: return "OP_MAX";
    case 0xA6: return "OP_RIPEMD160";
    case 0xA7: return "OP_SHA1";
    case 0xA8: return "OP_SHA256";
    case 0xA9: return "OP_HASH160";
    case 0xAA: return "OP_HASH256";
    case 0xAC: return "OP_CHECKSIG";
    case 0xAD: return "OP_CHECKSIGVERIFY";
    case 0xAE: return "OP_CHECKMULTISIG";
    case 0xAF: return "OP_CHECKMULTISIGVERIFY";
    case 0xB6: return "OP_LSHIFTNUM";
    case 0xB7: return "OP_RSHIFTNUM";
    default:   return "OP_UNKNOWN";
    }
}

static int parse_chunk(PyObject *t, int *op, const unsigned char **data,
                       Py_ssize_t *dlen) {
    *op = (int)PyLong_AsLong(PyTuple_GET_ITEM(t, 0));
    if (*op == -1 && PyErr_Occurred()) return -1;
    PyObject *d = PyTuple_GET_ITEM(t, 1);
    if (d == Py_None) { *data = NULL; *dlen = 0; }
    else { *data = (const unsigned char *)PyBytes_AS_STRING(d); *dlen = PyBytes_GET_SIZE(d); }
    return 0;
}

/* --- Internal hash helpers ---------------------------------------------- */

static void c_sha256_hash(const unsigned char *in, Py_ssize_t len,
                          unsigned char out[32]) {
    secp256k1_sha256 h;
    secp256k1_sha256_initialize(&h);
    if (len > 0) secp256k1_sha256_write(&h, in, len);
    secp256k1_sha256_finalize(&h, out);
}

static void c_hash256_hash(const unsigned char *in, Py_ssize_t len,
                           unsigned char out[32]) {
    unsigned char tmp[32];
    c_sha256_hash(in, len, tmp);
    c_sha256_hash(tmp, 32, out);
}

static PyObject *c_ripemd160_hash(const unsigned char *in, Py_ssize_t len) {
    PyObject *mod = PyImport_ImportModule("Cryptodome.Hash.RIPEMD160");
    if (!mod) return NULL;
    PyObject *data = PyBytes_FromStringAndSize(
        (const char *)(in ? in : (const unsigned char *)""), len);
    if (!data) { Py_DECREF(mod); return NULL; }
    PyObject *hasher = PyObject_CallMethod(mod, "new", "O", data);
    Py_DECREF(data); Py_DECREF(mod);
    if (!hasher) return NULL;
    PyObject *digest = PyObject_CallMethod(hasher, "digest", NULL);
    Py_DECREF(hasher);
    return digest;
}

static PyObject *c_sha1_hash(const unsigned char *in, Py_ssize_t len) {
    PyObject *mod = PyImport_ImportModule("hashlib");
    if (!mod) return NULL;
    PyObject *data = PyBytes_FromStringAndSize(
        (const char *)(in ? in : (const unsigned char *)""), len);
    if (!data) { Py_DECREF(mod); return NULL; }
    PyObject *hasher = PyObject_CallMethod(mod, "sha1", "O", data);
    Py_DECREF(data); Py_DECREF(mod);
    if (!hasher) return NULL;
    PyObject *digest = PyObject_CallMethod(hasher, "digest", NULL);
    Py_DECREF(hasher);
    return digest;
}

/* --- Phase 3c: CHECKSIG internalization helpers -------------------------- */

static const uint8_t VALID_SIGHASH[] = {
    0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3,
    0x61, 0x62, 0x63, 0xE1, 0xE2, 0xE3
};

static int c_sighash_validate(uint8_t sh) {
    for (int i = 0; i < 12; i++)
        if (VALID_SIGHASH[i] == sh) return 1;
    return 0;
}

static int c_sighash_use_otda(uint8_t sh) {
    return (sh & 0x20) != 0;
}

static size_t c_encode_pushdata(const unsigned char *data, Py_ssize_t dlen,
                                unsigned char *out) {
    if (data == NULL || dlen == 0) {
        out[0] = 0x00;
        return 1;
    }
    if (dlen == 1 && data[0] >= 1 && data[0] <= 16) {
        out[0] = 0x51 + data[0] - 1;
        return 1;
    }
    if (dlen == 1 && data[0] == 0x81) {
        out[0] = 0x4F;
        return 1;
    }
    if (dlen <= 75) {
        out[0] = (unsigned char)dlen;
        memcpy(out + 1, data, dlen);
        return 1 + (size_t)dlen;
    }
    if (dlen <= 255) {
        out[0] = 0x4C;
        out[1] = (unsigned char)dlen;
        memcpy(out + 2, data, dlen);
        return 2 + (size_t)dlen;
    }
    if (dlen <= 65535) {
        out[0] = 0x4D;
        out[1] = dlen & 0xFF;
        out[2] = (dlen >> 8) & 0xFF;
        memcpy(out + 3, data, dlen);
        return 3 + (size_t)dlen;
    }
    out[0] = 0x4E;
    out[1] = dlen & 0xFF;
    out[2] = (dlen >> 8) & 0xFF;
    out[3] = (dlen >> 16) & 0xFF;
    out[4] = (dlen >> 24) & 0xFF;
    memcpy(out + 5, data, dlen);
    return 5 + (size_t)dlen;
}

static int c_build_subscript(VMState *st,
                             const unsigned char **sigs, const Py_ssize_t *sig_lens,
                             Py_ssize_t n_sigs,
                             unsigned char **out_buf, size_t *out_len) {
    PyObject *chunks = (st->context == VM_CTX_UNLOCK)
                       ? st->unlock_chunks : st->lock_chunks;
    Py_ssize_t clen = PyList_GET_SIZE(chunks);
    Py_ssize_t start = st->last_code_separator;

    size_t cap = 256;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) { PyErr_NoMemory(); return -1; }
    size_t pos = 0;

    for (Py_ssize_t i = start; i < clen; i++) {
        int op; const unsigned char *data; Py_ssize_t dlen;
        if (parse_chunk(PyList_GET_ITEM(chunks, i), &op, &data, &dlen) < 0) {
            free(buf); return -1;
        }

        int skip = 0;
        if (data != NULL) {
            for (Py_ssize_t s = 0; s < n_sigs; s++) {
                if (dlen == sig_lens[s] && (dlen == 0 ||
                        memcmp(data, sigs[s], dlen) == 0)) {
                    skip = 1; break;
                }
            }
        }
        if (skip) continue;

        size_t need = (data != NULL) ? (size_t)dlen + 6 : 1;
        while (pos + need > cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)realloc(buf, cap);
            if (!nb) { free(buf); PyErr_NoMemory(); return -1; }
            buf = nb;
        }

        if (data != NULL) {
            pos += c_encode_pushdata(data, dlen, buf + pos);
        } else {
            buf[pos++] = (unsigned char)op;
        }
    }

    *out_buf = buf;
    *out_len = pos;
    return 0;
}

static int c_build_bip143_preimage(PreimageCtx *pctx,
                                   const unsigned char *subscript, size_t sub_len,
                                   uint32_t sighash,
                                   unsigned char **out, size_t *out_len) {
    static const unsigned char zeroes32[32] = {0};
    uint32_t base = sighash & 0x1F;

    const unsigned char *hp = (sighash & 0x80) ? zeroes32 : pctx->hash_prevouts;
    const unsigned char *hs = ((sighash & 0x80) || base == 0x02 || base == 0x03)
                              ? zeroes32 : pctx->hash_sequence;

    unsigned char single_ho[32];
    const unsigned char *ho;
    if (base != 0x03 && base != 0x02) {
        ho = pctx->hash_outputs;
    } else if (base == 0x03 && pctx->input_index < pctx->n_outputs) {
        PyObject *ob = PyList_GET_ITEM(pctx->outputs_list, pctx->input_index);
        hash256_var((const unsigned char *)PyBytes_AS_STRING(ob),
                    PyBytes_GET_SIZE(ob), single_ho);
        ho = single_ho;
    } else {
        ho = zeroes32;
    }

    int vi_len = varint_size(sub_len);
    size_t pre_len = 4 + 32 + 32 + 36 + vi_len + sub_len + 8 + 4 + 32 + 4 + 4;
    unsigned char *pre = (unsigned char *)malloc(pre_len);
    if (!pre) { PyErr_NoMemory(); return -1; }

    size_t p = 0;
    write_u32_le(pre + p, pctx->version); p += 4;
    memcpy(pre + p, hp, 32); p += 32;
    memcpy(pre + p, hs, 32); p += 32;
    memcpy(pre + p, pctx->cur_txid_le, 32); p += 32;
    write_u32_le(pre + p, pctx->cur_vout); p += 4;
    p += write_varint(pre + p, sub_len);
    memcpy(pre + p, subscript, sub_len); p += sub_len;
    write_u64_le(pre + p, (uint64_t)pctx->cur_satoshis); p += 8;
    write_u32_le(pre + p, pctx->cur_sequence); p += 4;
    memcpy(pre + p, ho, 32); p += 32;
    write_u32_le(pre + p, pctx->locktime); p += 4;
    write_u32_le(pre + p, sighash); p += 4;

    *out = pre;
    *out_len = p;
    return 0;
}

static int c_build_otda_preimage(PreimageCtx *pctx,
                                 const unsigned char *subscript, size_t sub_len,
                                 uint32_t sighash,
                                 unsigned char **out, size_t *out_len) {
    uint32_t base_type = sighash & 0x1F;
    int anyonecanpay = sighash & 0x80;
    Py_ssize_t total = pctx->n_other + 1;

    size_t est = 4 + 9;
    for (Py_ssize_t i = 0; i < total; i++) {
        if (i == pctx->input_index) {
            est += 36 + 9 + sub_len + 4;
        } else {
            est += 36 + 1 + 4;
        }
    }
    est += 9;
    for (Py_ssize_t i = 0; i < pctx->n_outputs; i++) {
        PyObject *ob = PyList_GET_ITEM(pctx->outputs_list, i);
        est += PyBytes_GET_SIZE(ob);
    }
    est += 4 + 4 + 100;

    unsigned char *buf = (unsigned char *)malloc(est);
    if (!buf) { PyErr_NoMemory(); return -1; }
    size_t p = 0;

    write_u32_le(buf + p, pctx->version); p += 4;

    Py_ssize_t in_count = anyonecanpay ? 1 : total;
    p += write_varint(buf + p, in_count);

    for (Py_ssize_t i = 0; i < total; i++) {
        if (anyonecanpay && i != pctx->input_index) continue;

        if (i == pctx->input_index) {
            memcpy(buf + p, pctx->cur_txid_le, 32); p += 32;
            write_u32_le(buf + p, pctx->cur_vout); p += 4;
            p += write_varint(buf + p, sub_len);
            memcpy(buf + p, subscript, sub_len); p += sub_len;
            write_u32_le(buf + p, pctx->cur_sequence); p += 4;
        } else {
            Py_ssize_t oi = (i < pctx->input_index) ? i : i - 1;
            PCtxInput *inp = &pctx->other_inputs[oi];
            memcpy(buf + p, inp->txid_le, 32); p += 32;
            write_u32_le(buf + p, inp->vout); p += 4;
            buf[p++] = 0x00;
            if (i != pctx->input_index &&
                (base_type == 0x02 || base_type == 0x03)) {
                write_u32_le(buf + p, 0); p += 4;
            } else {
                write_u32_le(buf + p, inp->sequence); p += 4;
            }
        }
    }

    if (base_type == 0x02) {
        buf[p++] = 0x00;
    } else if (base_type == 0x03) {
        Py_ssize_t out_count = pctx->input_index + 1;
        p += write_varint(buf + p, out_count);
        for (Py_ssize_t i = 0; i < out_count; i++) {
            if (i < pctx->input_index) {
                write_u64_le(buf + p, 0xFFFFFFFFFFFFFFFFULL); p += 8;
                buf[p++] = 0x00;
            } else {
                PyObject *ob = PyList_GET_ITEM(pctx->outputs_list, i);
                Py_ssize_t olen = PyBytes_GET_SIZE(ob);
                memcpy(buf + p, PyBytes_AS_STRING(ob), olen); p += olen;
            }
        }
    } else {
        p += write_varint(buf + p, pctx->n_outputs);
        for (Py_ssize_t i = 0; i < pctx->n_outputs; i++) {
            PyObject *ob = PyList_GET_ITEM(pctx->outputs_list, i);
            Py_ssize_t olen = PyBytes_GET_SIZE(ob);
            memcpy(buf + p, PyBytes_AS_STRING(ob), olen); p += olen;
        }
    }

    write_u32_le(buf + p, pctx->locktime); p += 4;
    write_u32_le(buf + p, sighash); p += 4;

    *out = buf;
    *out_len = p;
    return 0;
}

static int c_checksig_verify(VMState *st,
                             const unsigned char *sig_raw, Py_ssize_t sig_len,
                             const unsigned char *pub_raw, Py_ssize_t pub_len,
                             const unsigned char *subscript, size_t sub_len) {
    if (sig_len == 0) return 0;

    uint8_t sighash_byte = sig_raw[sig_len - 1];

    if (!c_sighash_validate(sighash_byte)) return -1;

    secp256k1_ecdsa_signature parsed_sig;
    if (!secp256k1_ecdsa_signature_parse_der(g_ctx, &parsed_sig,
            sig_raw, sig_len - 1))
        return -3;

    secp256k1_ecdsa_signature norm_sig;
    int was_high = secp256k1_ecdsa_signature_normalize(g_ctx, &norm_sig,
                                                       &parsed_sig);
    if (was_high && !(st->tx_version > 1))
        return -2;

    secp256k1_pubkey parsed_pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &parsed_pk, pub_raw, pub_len))
        return -4;

    unsigned char *preimage;
    size_t pre_len;
    int rc;
    if (c_sighash_use_otda(sighash_byte))
        rc = c_build_otda_preimage(&st->pctx, subscript, sub_len,
                                   sighash_byte, &preimage, &pre_len);
    else
        rc = c_build_bip143_preimage(&st->pctx, subscript, sub_len,
                                     sighash_byte, &preimage, &pre_len);
    if (rc < 0) return -5;

    unsigned char msg32[32];
    c_hash256_hash(preimage, pre_len, msg32);
    free(preimage);

    int ok = secp256k1_ecdsa_verify(g_ctx, &norm_sig, msg32, &parsed_pk);
    return ok ? 1 : 0;
}

/* --- vm_step: execute one opcode ---------------------------------------- */
/* Returns: 0 = success (increment PC), 1 = don't increment PC, -1 = error */

static int vm_step(VMState *st) {
    Py_ssize_t ulen = PyList_GET_SIZE(st->unlock_chunks);

    if (st->context == VM_CTX_UNLOCK && st->program_counter >= ulen) {
        st->context = VM_CTX_LOCK;
        st->program_counter = 0;
    }

    PyObject *chunks = (st->context == VM_CTX_UNLOCK)
                       ? st->unlock_chunks : st->lock_chunks;
    Py_ssize_t clen = PyList_GET_SIZE(chunks);
    if (st->program_counter >= clen) return 1;

    PyObject *chunk = PyList_GET_ITEM(chunks, st->program_counter);
    int op; const unsigned char *data; Py_ssize_t dlen;
    if (parse_chunk(chunk, &op, &data, &dlen) < 0) return -1;

    int is_exec = ifs_all_true(&st->if_stack);

    if (op < 0x00 || op > 0xFF) {
        vm_errorf(st, "An opcode is missing in this chunk of the %s!",
                  st->context == VM_CTX_UNLOCK ? "UnlockingScript" : "LockingScript");
        return -1;
    }
    if (data && dlen > VM_MAX_ELEM_SIZE) {
        vm_errorf(st, "It's not currently possible to push data larger than %d bytes.",
                  VM_MAX_ELEM_SIZE);
        return -1;
    }

    /* Data push (OP_0 through OP_PUSHDATA4: 0x00-0x4E) */
    if (is_exec && op >= 0x00 && op <= 0x4E) {
        if (!(st->tx_version > 1) && !c_is_chunk_minimal(op, data, dlen)) {
            vm_error(st, "This data is not minimally-encoded.");
            return -1;
        }
        if (!data || dlen == 0)
            return vms_push(&st->stack, NULL, 0) < 0 ? -1 : 0;
        return vms_push(&st->stack, data, dlen) < 0 ? -1 : 0;
    }

    if (!is_exec && !(op >= 0x63 && op <= 0x68)) return 0;

    switch (op) {

    /* ---- Constants ------------------------------------------------------ */
    case 0x4F: {
        unsigned char b = 0x81;
        return vms_push(&st->stack, &b, 1) < 0 ? -1 : 0;
    }
    case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
    case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A:
    case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x60: {
        unsigned char b = (unsigned char)(op - 0x50);
        return vms_push(&st->stack, &b, 1) < 0 ? -1 : 0;
    }

    /* ---- Flow control --------------------------------------------------- */
    case 0x62: { /* OP_VER */
        unsigned char ver[4];
        ver[0] = st->tx_version & 0xFF;
        ver[1] = (st->tx_version >> 8) & 0xFF;
        ver[2] = (st->tx_version >> 16) & 0xFF;
        ver[3] = (st->tx_version >> 24) & 0xFF;
        return vms_push(&st->stack, ver, 4) < 0 ? -1 : 0;
    }
    case 0x65: case 0x66: { /* OP_VERIF / OP_VERNOTIF */
        if (st->stack.count < 1) {
            vm_error(st, "OP_VERIF/OP_VERNOTIF requires at least one item on the stack.");
            return -1;
        }
        StackElem e; vms_pop(&st->stack, &e);
        int fv = 0;
        if (e.len == 4) {
            unsigned char ver[4];
            ver[0] = st->tx_version & 0xFF;
            ver[1] = (st->tx_version >> 8) & 0xFF;
            ver[2] = (st->tx_version >> 16) & 0xFF;
            ver[3] = (st->tx_version >> 24) & 0xFF;
            fv = (memcmp(e.data, ver, 4) == 0);
        }
        se_free(&e);
        if (op == 0x66) fv = !fv;
        return ifs_push(&st->if_stack, fv ? 1 : 0) < 0 ? -1 : 0;
    }
    case 0x63: case 0x64: { /* OP_IF / OP_NOTIF */
        int f = 0;
        if (is_exec) {
            if (st->stack.count < 1) {
                vm_error(st, "OP_IF and OP_NOTIF require at least one item on the stack when they are used!");
                return -1;
            }
            StackElem *top = vms_top(&st->stack, -1);
            if (!(st->tx_version > 1)) {
                if (top->len > 1) {
                    vm_error(st, "OP_IF/OP_NOTIF condition is not minimally encoded (length must be 0 or 1).");
                    return -1;
                }
                if (top->len == 1 && top->data[0] != 1) {
                    vm_error(st, "OP_IF/OP_NOTIF condition is not minimally encoded (must be empty or 0x01).");
                    return -1;
                }
            }
            f = c_cast_to_bool(top->data, top->len);
            if (op == 0x64) f = !f;
            vms_pop(&st->stack, NULL);
        }
        return ifs_push(&st->if_stack, f ? 1 : 0) < 0 ? -1 : 0;
    }
    case 0x67: { /* OP_ELSE */
        if (st->if_stack.count == 0) {
            vm_error(st, "OP_ELSE requires a preceeding OP_IF.");
            return -1;
        }
        st->if_stack.flags[st->if_stack.count - 1] ^= 1;
        return 0;
    }
    case 0x68: { /* OP_ENDIF */
        if (st->if_stack.count == 0) {
            vm_error(st, "OP_ENDIF requires a preceeding OP_IF.");
            return -1;
        }
        st->if_stack.count--;
        return 0;
    }
    case 0x69: { /* OP_VERIFY */
        if (st->stack.count < 1) {
            vm_error(st, "OP_VERIFY requires at least one item to be on the stack.");
            return -1;
        }
        StackElem *top = vms_top(&st->stack, -1);
        if (c_cast_to_bool(top->data, top->len)) {
            vms_pop(&st->stack, NULL);
            return 0;
        }
        vm_error(st, "OP_VERIFY requires the top stack value to be truthy.");
        return -1;
    }
    case 0x6A: { /* OP_RETURN */
        PyObject *ch = (st->context == VM_CTX_UNLOCK)
                       ? st->unlock_chunks : st->lock_chunks;
        st->program_counter = PyList_GET_SIZE(ch);
        st->if_stack.count = 0;
        return 1;
    }

    /* ---- NOP variants --------------------------------------------------- */
    case 0x61:
    case 0xB0: case 0xB1: case 0xB2:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
    case 0xC0: case 0xC1: case 0xC2: case 0xC3:
    case 0xC4: case 0xC5: case 0xC6: case 0xC7:
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD4: case 0xD5: case 0xD6: case 0xD7:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
    case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF0: case 0xF1: case 0xF2: case 0xF3:
    case 0xF4: case 0xF5: case 0xF6: case 0xF7:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC:
        return 0;

    /* ---- Stack manipulation --------------------------------------------- */
    case 0x6B: { /* OP_TOALTSTACK */
        if (st->stack.count < 1) {
            vm_error(st, "OP_TOALTSTACK requires at least one item to be on the stack.");
            return -1;
        }
        StackElem e; vms_pop(&st->stack, &e);
        return vms_push_take(&st->alt_stack, e.data, e.len) < 0 ? -1 : 0;
    }
    case 0x6C: { /* OP_FROMALTSTACK */
        if (st->alt_stack.count < 1) {
            vm_error(st, "OP_FROMALTSTACK requires at least one item to be on the stack.");
            return -1;
        }
        StackElem e; vms_pop(&st->alt_stack, &e);
        return vms_push_take(&st->stack, e.data, e.len) < 0 ? -1 : 0;
    }
    case 0x6D: { /* OP_2DROP */
        if (st->stack.count < 2) {
            vm_error(st, "OP_2DROP requires at least two items to be on the stack.");
            return -1;
        }
        vms_pop(&st->stack, NULL);
        vms_pop(&st->stack, NULL);
        return 0;
    }
    case 0x6E: { /* OP_2DUP */
        if (st->stack.count < 2) {
            vm_error(st, "OP_2DUP requires at least two items to be on the stack.");
            return -1;
        }
        if (vms_ensure(&st->stack, 2) < 0) return -1;
        StackElem *a = vms_top(&st->stack, -2);
        if (vms_push(&st->stack, a->data, a->len) < 0) return -1;
        StackElem *b = vms_top(&st->stack, -2);
        return vms_push(&st->stack, b->data, b->len) < 0 ? -1 : 0;
    }
    case 0x6F: { /* OP_3DUP */
        if (st->stack.count < 3) {
            vm_error(st, "OP_3DUP requires at least three items to be on the stack.");
            return -1;
        }
        if (vms_ensure(&st->stack, 3) < 0) return -1;
        StackElem *a = vms_top(&st->stack, -3);
        if (vms_push(&st->stack, a->data, a->len) < 0) return -1;
        StackElem *b = vms_top(&st->stack, -3);
        if (vms_push(&st->stack, b->data, b->len) < 0) return -1;
        StackElem *c = vms_top(&st->stack, -3);
        return vms_push(&st->stack, c->data, c->len) < 0 ? -1 : 0;
    }
    case 0x70: { /* OP_2OVER */
        if (st->stack.count < 4) {
            vm_error(st, "OP_2OVER requires at least four items to be on the stack.");
            return -1;
        }
        if (vms_ensure(&st->stack, 2) < 0) return -1;
        StackElem *a = vms_top(&st->stack, -4);
        if (vms_push(&st->stack, a->data, a->len) < 0) return -1;
        StackElem *b = vms_top(&st->stack, -4);
        return vms_push(&st->stack, b->data, b->len) < 0 ? -1 : 0;
    }
    case 0x71: { /* OP_2ROT */
        if (st->stack.count < 6) {
            vm_error(st, "OP_2ROT requires at least six items to be on the stack.");
            return -1;
        }
        Py_ssize_t idx = st->stack.count - 6;
        StackElem x1, x2;
        vms_remove(&st->stack, idx, &x1);
        vms_remove(&st->stack, idx, &x2);
        if (vms_push_take(&st->stack, x1.data, x1.len) < 0) {
            se_free(&x2); return -1;
        }
        return vms_push_take(&st->stack, x2.data, x2.len) < 0 ? -1 : 0;
    }
    case 0x72: { /* OP_2SWAP */
        if (st->stack.count < 4) {
            vm_error(st, "OP_2SWAP requires at least four items to be on the stack.");
            return -1;
        }
        Py_ssize_t idx = st->stack.count - 4;
        StackElem x1, x2;
        vms_remove(&st->stack, idx, &x1);
        vms_remove(&st->stack, idx, &x2);
        if (vms_push_take(&st->stack, x1.data, x1.len) < 0) {
            se_free(&x2); return -1;
        }
        return vms_push_take(&st->stack, x2.data, x2.len) < 0 ? -1 : 0;
    }
    case 0x73: { /* OP_IFDUP */
        if (st->stack.count < 1) {
            vm_error(st, "OP_IFDUP requires at least one item to be on the stack.");
            return -1;
        }
        StackElem *top = vms_top(&st->stack, -1);
        if (c_cast_to_bool(top->data, top->len)) {
            if (vms_ensure(&st->stack, 1) < 0) return -1;
            top = vms_top(&st->stack, -1);
            return vms_push(&st->stack, top->data, top->len) < 0 ? -1 : 0;
        }
        return 0;
    }
    case 0x74: { /* OP_DEPTH */
        PyObject *d = PyLong_FromSsize_t(st->stack.count);
        if (!d) return -1;
        int rc = vms_push_num(&st->stack, d);
        Py_DECREF(d);
        return rc < 0 ? -1 : 0;
    }
    case 0x75: { /* OP_DROP */
        if (st->stack.count < 1) {
            vm_error(st, "OP_DROP requires at least one item to be on the stack.");
            return -1;
        }
        vms_pop(&st->stack, NULL);
        return 0;
    }
    case 0x76: { /* OP_DUP */
        if (st->stack.count < 1) {
            vm_error(st, "OP_DUP requires at least one item to be on the stack.");
            return -1;
        }
        if (vms_ensure(&st->stack, 1) < 0) return -1;
        StackElem *top = vms_top(&st->stack, -1);
        return vms_push(&st->stack, top->data, top->len) < 0 ? -1 : 0;
    }
    case 0x77: { /* OP_NIP */
        if (st->stack.count < 2) {
            vm_error(st, "OP_NIP requires at least two items to be on the stack.");
            return -1;
        }
        vms_remove(&st->stack, st->stack.count - 2, NULL);
        return 0;
    }
    case 0x78: { /* OP_OVER */
        if (st->stack.count < 2) {
            vm_error(st, "OP_OVER requires at least two items to be on the stack.");
            return -1;
        }
        if (vms_ensure(&st->stack, 1) < 0) return -1;
        StackElem *e = vms_top(&st->stack, -2);
        return vms_push(&st->stack, e->data, e->len) < 0 ? -1 : 0;
    }
    case 0x79: case 0x7A: { /* OP_PICK / OP_ROLL */
        const char *name = vm_opname(op);
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least two items to be on the stack.", name);
            return -1;
        }
        StackElem *ne = vms_top(&st->stack, -1);
        PyObject *nobj = c_bin2num(ne->data, ne->len);
        if (!nobj) return -1;
        long long n = PyLong_AsLongLong(nobj);
        Py_DECREF(nobj);
        if (PyErr_Occurred()) { PyErr_Clear(); n = -1; }
        vms_pop(&st->stack, NULL);
        if (n < 0 || n >= st->stack.count) {
            vm_errorf(st, "%s requires the top stack element to be 0 or "
                "a positive number less than the current size of the stack.", name);
            return -1;
        }
        Py_ssize_t idx = st->stack.count - (Py_ssize_t)n - 1;
        if (op == 0x7A) {
            StackElem e;
            vms_remove(&st->stack, idx, &e);
            return vms_push_take(&st->stack, e.data, e.len) < 0 ? -1 : 0;
        }
        if (vms_ensure(&st->stack, 1) < 0) return -1;
        StackElem *src = &st->stack.items[idx];
        return vms_push(&st->stack, src->data, src->len) < 0 ? -1 : 0;
    }
    case 0x7B: { /* OP_ROT */
        if (st->stack.count < 3) {
            vm_error(st, "OP_ROT requires at least three items to be on the stack.");
            return -1;
        }
        Py_ssize_t c = st->stack.count;
        StackElem tmp = st->stack.items[c - 3];
        st->stack.items[c - 3] = st->stack.items[c - 2];
        st->stack.items[c - 2] = st->stack.items[c - 1];
        st->stack.items[c - 1] = tmp;
        return 0;
    }
    case 0x7C: { /* OP_SWAP */
        if (st->stack.count < 2) {
            vm_error(st, "OP_SWAP requires at least two items to be on the stack.");
            return -1;
        }
        Py_ssize_t c = st->stack.count;
        StackElem tmp = st->stack.items[c - 2];
        st->stack.items[c - 2] = st->stack.items[c - 1];
        st->stack.items[c - 1] = tmp;
        return 0;
    }
    case 0x7D: { /* OP_TUCK */
        if (st->stack.count < 2) {
            vm_error(st, "OP_TUCK requires at least two items to be on the stack.");
            return -1;
        }
        if (vms_ensure(&st->stack, 1) < 0) return -1;
        StackElem *top = vms_top(&st->stack, -1);
        unsigned char *copy = NULL;
        Py_ssize_t clen = top->len;
        if (clen > 0) {
            copy = (unsigned char *)PyMem_Malloc(clen);
            if (!copy) { PyErr_NoMemory(); return -1; }
            memcpy(copy, top->data, clen);
        }
        Py_ssize_t ins = st->stack.count - 2;
        memmove(&st->stack.items[ins + 1], &st->stack.items[ins],
                2 * sizeof(StackElem));
        st->stack.items[ins].data = copy;
        st->stack.items[ins].len = clen;
        st->stack.count++;
        return 0;
    }
    case 0x82: { /* OP_SIZE */
        if (st->stack.count < 1) {
            vm_error(st, "OP_SIZE requires at least one item to be on the stack.");
            return -1;
        }
        StackElem *top = vms_top(&st->stack, -1);
        PyObject *sz = PyLong_FromSsize_t(top->len);
        if (!sz) return -1;
        int rc = vms_push_num(&st->stack, sz);
        Py_DECREF(sz);
        return rc < 0 ? -1 : 0;
    }

    /* ---- Bitwise -------------------------------------------------------- */
    case 0x83: { /* OP_INVERT */
        if (st->stack.count < 1) {
            vm_error(st, "OP_INVERT requires at least one item to be on the stack.");
            return -1;
        }
        StackElem e; vms_pop(&st->stack, &e);
        for (Py_ssize_t i = 0; i < e.len; i++) e.data[i] ^= 0xFF;
        return vms_push_take(&st->stack, e.data, e.len) < 0 ? -1 : 0;
    }
    case 0x84: case 0x85: case 0x86: { /* OP_AND / OR / XOR */
        const char *name = vm_opname(op);
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least one item to be on the stack.", name);
            return -1;
        }
        StackElem a, b;
        vms_remove(&st->stack, st->stack.count - 2, &a);
        vms_pop(&st->stack, &b);
        if (a.len != b.len) {
            se_free(&a); se_free(&b);
            vm_errorf(st, "%s requires the top two stack items to be the same size.", name);
            return -1;
        }
        unsigned char *res = NULL;
        if (a.len > 0) {
            res = (unsigned char *)PyMem_Malloc(a.len);
            if (!res) { se_free(&a); se_free(&b); PyErr_NoMemory(); return -1; }
            for (Py_ssize_t i = 0; i < a.len; i++) {
                if (op == 0x84)      res[i] = a.data[i] & b.data[i];
                else if (op == 0x85) res[i] = a.data[i] | b.data[i];
                else                 res[i] = a.data[i] ^ b.data[i];
            }
        }
        Py_ssize_t rlen = a.len;
        se_free(&a); se_free(&b);
        return vms_push_take(&st->stack, res, rlen) < 0 ? -1 : 0;
    }
    case 0x98: case 0x99: { /* OP_LSHIFT / OP_RSHIFT */
        const char *name = vm_opname(op);
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least two items to be on the stack.", name);
            return -1;
        }
        StackElem *ne = vms_top(&st->stack, -1);
        PyObject *nobj = c_bin2num(ne->data, ne->len);
        if (!nobj) return -1;
        long long n = PyLong_AsLongLong(nobj);
        Py_DECREF(nobj);
        if (PyErr_Occurred()) { PyErr_Clear(); n = -1; }
        if (n < 0) {
            vm_errorf(st, "%s requires the top stack item to be non-negative.", name);
            return -1;
        }
        StackElem x;
        vms_remove(&st->stack, st->stack.count - 2, &x);
        unsigned char *res = NULL; Py_ssize_t rlen = 0;
        if (op == 0x98) {
            Py_ssize_t keep = (n < x.len) ? x.len - (Py_ssize_t)n : 0;
            rlen = keep + (Py_ssize_t)n;
            if (rlen > 0) {
                res = (unsigned char *)PyMem_Malloc(rlen);
                if (!res) { se_free(&x); PyErr_NoMemory(); return -1; }
                if (keep > 0) memcpy(res, x.data + n, keep);
                memset(res + keep, 0, (size_t)n);
            }
        } else {
            if (n == 0) {
                rlen = 0; res = NULL;
            } else {
                Py_ssize_t keep = ((Py_ssize_t)n < x.len) ? x.len - (Py_ssize_t)n : 0;
                rlen = (Py_ssize_t)n + keep;
                if (rlen > 0) {
                    res = (unsigned char *)PyMem_Malloc(rlen);
                    if (!res) { se_free(&x); PyErr_NoMemory(); return -1; }
                    memset(res, 0, (size_t)n);
                    if (keep > 0) memcpy(res + n, x.data, keep);
                }
            }
        }
        se_free(&x);
        return vms_push_take(&st->stack, res, rlen) < 0 ? -1 : 0;
    }

    /* ---- Comparison ----------------------------------------------------- */
    case 0x87: case 0x88: { /* OP_EQUAL / OP_EQUALVERIFY */
        const char *name = vm_opname(op);
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least two items to be on the stack.", name);
            return -1;
        }
        StackElem a, b;
        vms_remove(&st->stack, st->stack.count - 2, &a);
        vms_pop(&st->stack, &b);
        int f = (a.len == b.len) &&
                (a.len == 0 || memcmp(a.data, b.data, a.len) == 0);
        se_free(&a); se_free(&b);
        unsigned char bv = 0x01;
        if (vms_push(&st->stack, f ? &bv : NULL, f ? 1 : 0) < 0) return -1;
        if (op == 0x88) {
            if (f) { vms_pop(&st->stack, NULL); }
            else {
                vm_error(st, "OP_EQUALVERIFY requires the top two stack items to be equal.");
                return -1;
            }
        }
        return 0;
    }

    /* ---- Unary arithmetic ----------------------------------------------- */
    case 0x8B: case 0x8C: case 0x8F: case 0x90:
    case 0x91: case 0x92: {
        const char *name = vm_opname(op);
        if (st->stack.count < 1) {
            vm_errorf(st, "%s requires at least one items to be on the stack.", name);
            return -1;
        }
        PyObject *x = vms_pop_num(&st->stack);
        if (!x) return -1;
        PyObject *r = NULL;
        switch (op) {
        case 0x8B: { PyObject *o = PyLong_FromLong(1);
                     r = PyNumber_Add(x, o); Py_DECREF(o); break; }
        case 0x8C: { PyObject *o = PyLong_FromLong(1);
                     r = PyNumber_Subtract(x, o); Py_DECREF(o); break; }
        case 0x8F: r = PyNumber_Negative(x); break;
        case 0x90: r = PyNumber_Absolute(x); break;
        case 0x91: { int z = PyObject_Not(x);
                     if (z < 0) { Py_DECREF(x); return -1; }
                     r = PyLong_FromLong(z); break; }
        case 0x92: { int nz = PyObject_IsTrue(x);
                     if (nz < 0) { Py_DECREF(x); return -1; }
                     r = PyLong_FromLong(nz); break; }
        }
        Py_DECREF(x);
        if (!r) return -1;
        int rc = vms_push_num(&st->stack, r);
        Py_DECREF(r);
        return rc < 0 ? -1 : 0;
    }
    case 0x8D: case 0x8E: { /* OP_2MUL / OP_2DIV */
        const char *name = vm_opname(op);
        if (st->stack.count < 1) {
            vm_errorf(st, "%s requires at least one item to be on the stack.", name);
            return -1;
        }
        PyObject *x = vms_pop_num(&st->stack);
        if (!x) return -1;
        PyObject *two = PyLong_FromLong(2);
        PyObject *r = NULL;
        if (op == 0x8D) {
            r = PyNumber_Multiply(x, two);
        } else {
            PyObject *pz = PyLong_FromLong(0);
            int neg = PyObject_RichCompareBool(x, pz, Py_LT);
            Py_DECREF(pz);
            if (neg > 0) {
                PyObject *ax = PyNumber_Negative(x);
                PyObject *d = PyNumber_FloorDivide(ax, two);
                r = d ? PyNumber_Negative(d) : NULL;
                Py_XDECREF(ax); Py_XDECREF(d);
            } else {
                r = PyNumber_FloorDivide(x, two);
            }
        }
        Py_DECREF(x); Py_DECREF(two);
        if (!r) return -1;
        int rc = vms_push_num(&st->stack, r);
        Py_DECREF(r);
        return rc < 0 ? -1 : 0;
    }

    /* ---- Numeric shift -------------------------------------------------- */
    case 0xB6: case 0xB7: { /* OP_LSHIFTNUM / OP_RSHIFTNUM */
        const char *name = vm_opname(op);
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least two items on the stack.", name);
            return -1;
        }
        PyObject *shift = vms_pop_num(&st->stack);
        PyObject *value = vms_pop_num(&st->stack);
        if (!shift || !value) {
            Py_XDECREF(shift); Py_XDECREF(value); return -1;
        }
        PyObject *pz = PyLong_FromLong(0);
        int neg_shift = PyObject_RichCompareBool(shift, pz, Py_LT);
        if (neg_shift > 0) {
            Py_DECREF(shift); Py_DECREF(value); Py_DECREF(pz);
            vm_errorf(st, "%s: shift amount must be non-negative.", name);
            return -1;
        }
        PyObject *r = NULL;
        if (op == 0xB6) {
            r = PyNumber_Lshift(value, shift);
        } else {
            int neg_val = PyObject_RichCompareBool(value, pz, Py_LT);
            if (neg_val > 0) {
                PyObject *av = PyNumber_Negative(value);
                PyObject *sr = av ? PyNumber_Rshift(av, shift) : NULL;
                r = sr ? PyNumber_Negative(sr) : NULL;
                Py_XDECREF(av); Py_XDECREF(sr);
            } else {
                r = PyNumber_Rshift(value, shift);
            }
        }
        Py_DECREF(shift); Py_DECREF(value); Py_DECREF(pz);
        if (!r) return -1;
        int rc = vms_push_num(&st->stack, r);
        Py_DECREF(r);
        return rc < 0 ? -1 : 0;
    }

    /* ---- Binary arithmetic ---------------------------------------------- */
    case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E:
    case 0x9F: case 0xA0: case 0xA1: case 0xA2:
    case 0xA3: case 0xA4: {
        const char *name = vm_opname(op);
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least two items to be on the stack.", name);
            return -1;
        }
        PyObject *x1 = vms_remove_num(&st->stack, st->stack.count - 2);
        PyObject *x2 = vms_pop_num(&st->stack);
        if (!x1 || !x2) {
            Py_XDECREF(x1); Py_XDECREF(x2); return -1;
        }
        PyObject *r = NULL;
        PyObject *pz = PyLong_FromLong(0);
        switch (op) {
        case 0x93: r = PyNumber_Add(x1, x2); break;
        case 0x94: r = PyNumber_Subtract(x1, x2); break;
        case 0x95: r = PyNumber_Multiply(x1, x2); break;
        case 0x96:
            if (PyObject_RichCompareBool(x2, pz, Py_EQ) > 0) {
                Py_DECREF(x1); Py_DECREF(x2); Py_DECREF(pz);
                vm_error(st, "OP_DIV cannot divide by zero!");
                return -1;
            }
            r = PyNumber_FloorDivide(x1, x2); break;
        case 0x97:
            if (PyObject_RichCompareBool(x2, pz, Py_EQ) > 0) {
                Py_DECREF(x1); Py_DECREF(x2); Py_DECREF(pz);
                vm_error(st, "OP_MOD cannot divide by zero!");
                return -1;
            }
            r = PyNumber_Remainder(x1, x2); break;
        case 0x9A: {
            int a = PyObject_IsTrue(x1), b = PyObject_IsTrue(x2);
            r = PyLong_FromLong((a > 0 && b > 0) ? 1 : 0); break;
        }
        case 0x9B: {
            int a = PyObject_IsTrue(x1), b = PyObject_IsTrue(x2);
            r = PyLong_FromLong((a > 0 || b > 0) ? 1 : 0); break;
        }
        case 0x9C: case 0x9D: {
            int eq = PyObject_RichCompareBool(x1, x2, Py_EQ);
            r = PyLong_FromLong(eq > 0 ? 1 : 0); break;
        }
        case 0x9E: {
            int ne = PyObject_RichCompareBool(x1, x2, Py_NE);
            r = PyLong_FromLong(ne > 0 ? 1 : 0); break;
        }
        case 0x9F: {
            int lt = PyObject_RichCompareBool(x1, x2, Py_LT);
            r = PyLong_FromLong(lt > 0 ? 1 : 0); break;
        }
        case 0xA0: {
            int gt = PyObject_RichCompareBool(x1, x2, Py_GT);
            r = PyLong_FromLong(gt > 0 ? 1 : 0); break;
        }
        case 0xA1: {
            int le = PyObject_RichCompareBool(x1, x2, Py_LE);
            r = PyLong_FromLong(le > 0 ? 1 : 0); break;
        }
        case 0xA2: {
            int ge = PyObject_RichCompareBool(x1, x2, Py_GE);
            r = PyLong_FromLong(ge > 0 ? 1 : 0); break;
        }
        case 0xA3: {
            int lt = PyObject_RichCompareBool(x1, x2, Py_LT);
            r = (lt > 0) ? x1 : x2; Py_INCREF(r); break;
        }
        case 0xA4: {
            int gt = PyObject_RichCompareBool(x1, x2, Py_GT);
            r = (gt > 0) ? x1 : x2; Py_INCREF(r); break;
        }
        }
        Py_DECREF(x1); Py_DECREF(x2); Py_DECREF(pz);
        if (!r) return -1;
        int rc = vms_push_num(&st->stack, r);
        Py_DECREF(r);
        if (rc < 0) return -1;
        if (op == 0x9D) {
            StackElem *top = vms_top(&st->stack, -1);
            if (c_cast_to_bool(top->data, top->len)) {
                vms_pop(&st->stack, NULL);
            } else {
                vm_error(st, "OP_NUMEQUALVERIFY requires the top stack item to be truthy.");
                return -1;
            }
        }
        return 0;
    }

    /* ---- OP_WITHIN ------------------------------------------------------ */
    case 0xA5: {
        if (st->stack.count < 3) {
            vm_error(st, "OP_WITHIN requires at least three items to be on the stack.");
            return -1;
        }
        PyObject *x1 = vms_remove_num(&st->stack, st->stack.count - 3);
        PyObject *x2 = vms_remove_num(&st->stack, st->stack.count - 2);
        PyObject *x3 = vms_pop_num(&st->stack);
        if (!x1 || !x2 || !x3) {
            Py_XDECREF(x1); Py_XDECREF(x2); Py_XDECREF(x3); return -1;
        }
        int ge = PyObject_RichCompareBool(x2, x1, Py_LE);
        int lt = PyObject_RichCompareBool(x1, x3, Py_LT);
        int f = (ge > 0 && lt > 0);
        Py_DECREF(x1); Py_DECREF(x2); Py_DECREF(x3);
        unsigned char bv = 0x01;
        return vms_push(&st->stack, f ? &bv : NULL, f ? 1 : 0) < 0 ? -1 : 0;
    }

    /* ---- Hash opcodes --------------------------------------------------- */
    case 0xA6: case 0xA7: case 0xA8: case 0xA9: case 0xAA: {
        const char *name = vm_opname(op);
        if (st->stack.count < 1) {
            vm_errorf(st, "%s requires at least one item to be on the stack.", name);
            return -1;
        }
        StackElem e; vms_pop(&st->stack, &e);
        const unsigned char *inp = e.data;
        Py_ssize_t ilen = e.len;
        if (op == 0xA8 || op == 0xAA) {
            unsigned char hash[32];
            if (op == 0xA8) c_sha256_hash(inp, ilen, hash);
            else c_hash256_hash(inp, ilen, hash);
            se_free(&e);
            return vms_push(&st->stack, hash, 32) < 0 ? -1 : 0;
        }
        PyObject *digest = NULL;
        if (op == 0xA6) {
            digest = c_ripemd160_hash(inp, ilen);
        } else if (op == 0xA7) {
            digest = c_sha1_hash(inp, ilen);
        } else {
            unsigned char sha[32];
            c_sha256_hash(inp, ilen, sha);
            digest = c_ripemd160_hash(sha, 32);
        }
        se_free(&e);
        if (!digest) return -1;
        int rc = vms_push(&st->stack,
                          (const unsigned char *)PyBytes_AS_STRING(digest),
                          PyBytes_GET_SIZE(digest));
        Py_DECREF(digest);
        return rc < 0 ? -1 : 0;
    }
    case 0xAB: /* OP_CODESEPARATOR */
        st->last_code_separator = st->program_counter;
        return 0;

    /* ---- CHECKSIG / CHECKMULTISIG (Phase 3c: C internalization) ---------- */
    case 0xAC: case 0xAD: { /* OP_CHECKSIG / OP_CHECKSIGVERIFY */
        const char *name = (op == 0xAC) ? "OP_CHECKSIG" : "OP_CHECKSIGVERIFY";
        if (st->stack.count < 2) {
            vm_errorf(st, "%s requires at least two items to be on the stack.", name);
            return -1;
        }

        StackElem sig, pub_key;
        vms_remove(&st->stack, st->stack.count - 2, &sig);
        vms_pop(&st->stack, &pub_key);
        Py_ssize_t sig_len = sig.len;

        const unsigned char *sig_ptrs[1] = { sig.data };
        Py_ssize_t sig_lens[1] = { sig.len };
        unsigned char *subscript = NULL; size_t sub_len = 0;
        if (c_build_subscript(st, sig_ptrs, sig_lens, 1,
                              &subscript, &sub_len) < 0) {
            se_free(&sig); se_free(&pub_key); return -1;
        }

        int rv = c_checksig_verify(st, sig.data, sig.len,
                                   pub_key.data, pub_key.len,
                                   subscript, sub_len);
        free(subscript);
        se_free(&sig); se_free(&pub_key);

        if (rv == -5) return -1;
        if (rv < 0) {
            switch (rv) {
                case -1: vm_error(st, "Invalid SIGHASH flag"); break;
                case -2: vm_error(st, "The signature must have a low S value."); break;
                case -3: vm_error(st, "The signature format is invalid."); break;
                case -4: vm_errorf(st, "%s requires correct encoding for the "
                                  "public key and signature.", name); break;
                default: vm_error(st, "Unknown signature encoding error."); break;
            }
            return -1;
        }

        int f = (rv > 0) ? 1 : 0;

        if (!(st->tx_version > 1) && !f && sig_len > 0) {
            vm_errorf(st, "%s failed to verify the signature, "
                      "and requires an empty signature when verification fails.", name);
            return -1;
        }

        if (f) {
            unsigned char one = 1;
            if (vms_push(&st->stack, &one, 1) < 0) return -1;
        } else {
            if (vms_push(&st->stack, NULL, 0) < 0) return -1;
        }

        if (op == 0xAD) { /* CHECKSIGVERIFY */
            if (f) {
                vms_pop(&st->stack, NULL);
            } else {
                vm_error(st, "OP_CHECKSIGVERIFY requires that a valid signature is provided.");
                return -1;
            }
        }
        return 0;
    }

    case 0xAE: case 0xAF: { /* OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY */
        const char *name = (op == 0xAE) ? "OP_CHECKMULTISIG" : "OP_CHECKMULTISIGVERIFY";
        Py_ssize_t ii = 1;

        if (st->stack.count < ii) {
            vm_errorf(st, "%s requires at least 1 item to be on the stack.", name);
            return -1;
        }

        /* Read keys_count */
        StackElem *kc_elem = vms_top(&st->stack, -(int)ii);
        PyObject *kc_obj = c_bin2num(kc_elem->data, kc_elem->len);
        if (!kc_obj) return -1;
        long long keys_count = PyLong_AsLongLong(kc_obj);
        Py_DECREF(kc_obj);
        if (PyErr_Occurred()) { PyErr_Clear(); keys_count = -1; }

        if (keys_count < 0 || keys_count > VM_MAX_MULTISIG_KEY_COUNT) {
            vm_errorf(st, "$%s requires a key count between 0 and %lld.",
                      name, VM_MAX_MULTISIG_KEY_COUNT);
            return -1;
        }
        ii += 1;
        Py_ssize_t i_key = ii;
        ii += (Py_ssize_t)keys_count;

        Py_ssize_t i_key2 = (Py_ssize_t)keys_count + 2;

        if (st->stack.count < ii) {
            vm_errorf(st, "%s requires the number of stack items not to be "
                      "less than the number of keys used.", name);
            return -1;
        }

        /* Read sigs_count */
        StackElem *sc_elem = vms_top(&st->stack, -(int)ii);
        PyObject *sc_obj = c_bin2num(sc_elem->data, sc_elem->len);
        if (!sc_obj) return -1;
        long long sigs_count = PyLong_AsLongLong(sc_obj);
        Py_DECREF(sc_obj);
        if (PyErr_Occurred()) { PyErr_Clear(); sigs_count = -1; }

        if (sigs_count < 0 || sigs_count > keys_count) {
            vm_errorf(st, "%s requires the number of signatures to be "
                      "no greater than the number of keys.", name);
            return -1;
        }
        ii += 1;
        Py_ssize_t i_sig = ii;
        ii += (Py_ssize_t)sigs_count;

        if (st->stack.count < ii) {
            vm_errorf(st, "%s requires the number of stack items "
                      "not to be less than the number of signatures provided.", name);
            return -1;
        }

        /* Collect all sigs for subscript find_and_delete */
        const unsigned char **all_sig_ptrs = NULL;
        Py_ssize_t *all_sig_lens = NULL;
        if (sigs_count > 0) {
            all_sig_ptrs = (const unsigned char **)calloc(sigs_count, sizeof(unsigned char*));
            all_sig_lens = (Py_ssize_t *)calloc(sigs_count, sizeof(Py_ssize_t));
            if (!all_sig_ptrs || !all_sig_lens) {
                free(all_sig_ptrs); free(all_sig_lens);
                PyErr_NoMemory(); return -1;
            }
            for (Py_ssize_t j = 0; j < (Py_ssize_t)sigs_count; j++) {
                StackElem *se = vms_top(&st->stack, -(int)(i_sig + j));
                all_sig_ptrs[j] = se->data;
                all_sig_lens[j] = se->len;
            }
        }

        /* Build subscript once */
        unsigned char *subscript = NULL; size_t sub_len = 0;
        if (c_build_subscript(st, all_sig_ptrs, all_sig_lens,
                              (Py_ssize_t)sigs_count,
                              &subscript, &sub_len) < 0) {
            free(all_sig_ptrs); free(all_sig_lens);
            return -1;
        }
        free(all_sig_ptrs); free(all_sig_lens);

        /* Verification loop */
        int f = 1;
        long long rem_sigs = sigs_count;
        long long rem_keys = keys_count;
        Py_ssize_t loop_i_sig = i_sig;
        Py_ssize_t loop_i_key = i_key;

        while (f && rem_sigs > 0) {
            StackElem *se_sig = vms_top(&st->stack, -(int)loop_i_sig);
            StackElem *se_key = vms_top(&st->stack, -(int)loop_i_key);

            int rv = c_checksig_verify(st,
                se_sig->data, se_sig->len,
                se_key->data, se_key->len,
                subscript, sub_len);

            if (rv == -5) { free(subscript); return -1; }
            if (rv < 0) {
                free(subscript);
                switch (rv) {
                    case -1: vm_error(st, "Invalid SIGHASH flag"); break;
                    case -2: vm_error(st, "The signature must have a low S value."); break;
                    case -3: vm_error(st, "The signature format is invalid."); break;
                    case -4: vm_errorf(st, "%s requires correct encoding for the "
                                      "public key and signature.", name); break;
                    default: vm_error(st, "Unknown signature encoding error."); break;
                }
                return -1;
            }

            if (rv > 0) {
                loop_i_sig += 1;
                rem_sigs -= 1;
            }
            loop_i_key += 1;
            rem_keys -= 1;

            if (rem_sigs > rem_keys)
                f = 0;
        }

        free(subscript);

        /* Clean up stack of actual arguments */
        while (ii > 1) {
            if (i_key2 > 0) i_key2--;
            vms_pop(&st->stack, NULL);
            ii--;
        }

        /* Extra dummy item (NULLDUMMY) */
        if (st->stack.count < 1) {
            vm_errorf(st, "%s requires an extra item to be on the stack.", name);
            return -1;
        }
        {
            StackElem *dummy = vms_top(&st->stack, -1);
            if (!(st->tx_version > 1) && dummy->len > 0) {
                vm_errorf(st, "%s requires the extra stack item to be empty.", name);
                return -1;
            }
        }
        vms_pop(&st->stack, NULL);

        /* Push result */
        if (f) {
            unsigned char one = 1;
            if (vms_push(&st->stack, &one, 1) < 0) return -1;
        } else {
            if (vms_push(&st->stack, NULL, 0) < 0) return -1;
        }

        if (op == 0xAF) { /* CHECKMULTISIGVERIFY */
            if (f) {
                vms_pop(&st->stack, NULL);
            } else {
                vm_error(st, "OP_CHECKMULTISIGVERIFY requires a sufficient number "
                          "of valid signatures are provided.");
                return -1;
            }
        }
        return 0;
    }

    /* ---- String / splice ------------------------------------------------ */
    case 0x7E: { /* OP_CAT */
        if (st->stack.count < 2) {
            vm_error(st, "OP_CAT requires at least two items to be on the stack.");
            return -1;
        }
        StackElem a, b;
        vms_remove(&st->stack, st->stack.count - 2, &a);
        vms_pop(&st->stack, &b);
        Py_ssize_t total = a.len + b.len;
        if (total > VM_MAX_ELEM_SIZE) {
            se_free(&a); se_free(&b);
            vm_errorf(st, "It's not currently possible to push data larger than %d bytes.",
                      VM_MAX_ELEM_SIZE);
            return -1;
        }
        unsigned char *res = NULL;
        if (total > 0) {
            res = (unsigned char *)PyMem_Malloc(total);
            if (!res) { se_free(&a); se_free(&b); PyErr_NoMemory(); return -1; }
            if (a.len > 0) memcpy(res, a.data, a.len);
            if (b.len > 0) memcpy(res + a.len, b.data, b.len);
        }
        se_free(&a); se_free(&b);
        return vms_push_take(&st->stack, res, total) < 0 ? -1 : 0;
    }
    case 0x7F: { /* OP_SPLIT */
        if (st->stack.count < 2) {
            vm_error(st, "OP_SPLIT requires at least two items to be on the stack.");
            return -1;
        }
        StackElem x1;
        vms_remove(&st->stack, st->stack.count - 2, &x1);
        PyObject *nobj = vms_pop_num(&st->stack);
        if (!nobj) { se_free(&x1); return -1; }
        long long n = PyLong_AsLongLong(nobj);
        Py_DECREF(nobj);
        if (PyErr_Occurred()) { PyErr_Clear(); n = -1; }
        if (n < 0 || n > x1.len) {
            se_free(&x1);
            vm_error(st, "OP_SPLIT requires the first stack item to be a non-negative number "
                "less than or equal to the size of the second-from-top stack item.");
            return -1;
        }
        if (vms_push(&st->stack, x1.data, (Py_ssize_t)n) < 0) {
            se_free(&x1); return -1;
        }
        int rc = vms_push(&st->stack, x1.data + n, x1.len - (Py_ssize_t)n);
        se_free(&x1);
        return rc < 0 ? -1 : 0;
    }
    case 0xB3: { /* OP_SUBSTR */
        if (st->stack.count < 3) {
            vm_error(st, "OP_SUBSTR requires at least three items on the stack.");
            return -1;
        }
        PyObject *lobj = vms_pop_num(&st->stack);
        PyObject *sobj = vms_pop_num(&st->stack);
        StackElem dat; vms_pop(&st->stack, &dat);
        if (!lobj || !sobj) {
            Py_XDECREF(lobj); Py_XDECREF(sobj); se_free(&dat); return -1;
        }
        long long length = PyLong_AsLongLong(lobj);
        long long start  = PyLong_AsLongLong(sobj);
        Py_DECREF(lobj); Py_DECREF(sobj);
        if (dat.len == 0) {
            se_free(&dat);
            vm_error(st, "OP_SUBSTR: source string is empty.");
            return -1;
        }
        if (length < 0) {
            se_free(&dat);
            vm_error(st, "OP_SUBSTR: length is negative.");
            return -1;
        }
        if (start < 0 || start + length > dat.len) {
            se_free(&dat);
            vm_error(st, "OP_SUBSTR: specified range exceeds source string.");
            return -1;
        }
        int rc = vms_push(&st->stack, dat.data + start, (Py_ssize_t)length);
        se_free(&dat);
        return rc < 0 ? -1 : 0;
    }
    case 0xB4: { /* OP_LEFT */
        if (st->stack.count < 2) {
            vm_error(st, "OP_LEFT requires at least two items on the stack.");
            return -1;
        }
        PyObject *lobj = vms_pop_num(&st->stack);
        StackElem dat; vms_pop(&st->stack, &dat);
        if (!lobj) { se_free(&dat); return -1; }
        long long length = PyLong_AsLongLong(lobj);
        Py_DECREF(lobj);
        if (PyErr_Occurred()) { PyErr_Clear(); length = -1; }
        if (length < 0 || length > dat.len) {
            se_free(&dat);
            vm_error(st, "OP_LEFT: length out of range.");
            return -1;
        }
        int rc = vms_push(&st->stack, dat.data, (Py_ssize_t)length);
        se_free(&dat);
        return rc < 0 ? -1 : 0;
    }
    case 0xB5: { /* OP_RIGHT */
        if (st->stack.count < 2) {
            vm_error(st, "OP_RIGHT requires at least two items on the stack.");
            return -1;
        }
        PyObject *lobj = vms_pop_num(&st->stack);
        StackElem dat; vms_pop(&st->stack, &dat);
        if (!lobj) { se_free(&dat); return -1; }
        long long length = PyLong_AsLongLong(lobj);
        Py_DECREF(lobj);
        if (PyErr_Occurred()) { PyErr_Clear(); length = -1; }
        if (length < 0 || length > dat.len) {
            se_free(&dat);
            vm_error(st, "OP_RIGHT: length out of range.");
            return -1;
        }
        int rc = vms_push(&st->stack,
                          dat.data + dat.len - (Py_ssize_t)length,
                          (Py_ssize_t)length);
        se_free(&dat);
        return rc < 0 ? -1 : 0;
    }
    case 0x80: { /* OP_NUM2BIN */
        if (st->stack.count < 2) {
            vm_error(st, "OP_NUM2BIN requires at least two items to be on the stack.");
            return -1;
        }
        PyObject *sobj = vms_pop_num(&st->stack);
        if (!sobj) return -1;
        long long size = PyLong_AsLongLong(sobj);
        Py_DECREF(sobj);
        if (PyErr_Occurred()) { PyErr_Clear(); size = (long long)VM_MAX_ELEM_SIZE + 1; }
        if (size > VM_MAX_ELEM_SIZE) {
            vm_errorf(st, "It's not currently possible to push data larger than %d bytes.",
                      VM_MAX_ELEM_SIZE);
            return -1;
        }
        PyObject *n = vms_pop_num(&st->stack);
        if (!n) return -1;
        unsigned char *me; Py_ssize_t me_len;
        if (c_min_encode(n, &me, &me_len) < 0) { Py_DECREF(n); return -1; }
        Py_DECREF(n);
        if (me_len > size) {
            if (me) PyMem_Free(me);
            vm_error(st, "OP_NUM2BIN requires that the size expressed in the top stack item "
                "is large enough to hold the value expressed in the second-from-top stack item.");
            return -1;
        }
        if (size == 0) {
            if (me) PyMem_Free(me);
            return vms_push(&st->stack, NULL, 0) < 0 ? -1 : 0;
        }
        unsigned char msb = 0;
        if (me_len > 0) {
            msb = me[me_len - 1] & 0x80;
            me[me_len - 1] &= 0x7F;
        }
        unsigned char *res = (unsigned char *)PyMem_Malloc((Py_ssize_t)size);
        if (!res) { if (me) PyMem_Free(me); PyErr_NoMemory(); return -1; }
        if (me_len > 0) memcpy(res, me, me_len);
        memset(res + me_len, 0, (Py_ssize_t)size - me_len);
        res[(Py_ssize_t)size - 1] |= msb;
        if (me) PyMem_Free(me);
        return vms_push_take(&st->stack, res, (Py_ssize_t)size) < 0 ? -1 : 0;
    }
    case 0x81: { /* OP_BIN2NUM */
        if (st->stack.count < 1) {
            vm_error(st, "OP_BIN2NUM requires at least one item to be on the stack.");
            return -1;
        }
        PyObject *x = vms_pop_num(&st->stack);
        if (!x) return -1;
        int rc = vms_push_num(&st->stack, x);
        Py_DECREF(x);
        return rc < 0 ? -1 : 0;
    }

    default:
        vm_error(st, "Invalid opcode!");
        return -1;
    } /* end switch */
}

/* --- vm_run: main execution loop ---------------------------------------- */

static int vm_run(VMState *st) {
    if (!(st->tx_version > 1)) {
        Py_ssize_t n = PyList_GET_SIZE(st->unlock_chunks);
        for (Py_ssize_t i = 0; i < n; i++) {
            int uop = (int)PyLong_AsLong(
                PyTuple_GET_ITEM(PyList_GET_ITEM(st->unlock_chunks, i), 0));
            if (uop > 0x60) {
                vm_error(st, "Unlocking scripts can only contain push operations, "
                         "and no other opcodes.");
                return -1;
            }
        }
    }

    Py_ssize_t llen = PyList_GET_SIZE(st->lock_chunks);

    while (1) {
        int ret = vm_step(st);
        if (ret < 0) return -1;
        if (ret != 1) st->program_counter++;
        if (st->context == VM_CTX_LOCK && st->program_counter >= llen)
            break;
    }

    if (st->if_stack.count > 0) {
        vm_error(st, "Every OP_IF must be terminated prior to the end of the script.");
        return -1;
    }
    if (!(st->tx_version > 1)) {
        if (st->stack.count != 1) {
            vm_error(st, "The clean stack rule requires exactly one item "
                     "to be on the stack after script execution.");
            return -1;
        }
    }
    if (st->stack.count < 1) {
        vm_error(st, "The top stack element must be truthy after script evaluation.");
        return -1;
    }
    StackElem *top = vms_top(&st->stack, -1);
    if (!c_cast_to_bool(top->data, top->len)) {
        vm_error(st, "The top stack element must be truthy after script evaluation.");
        return -1;
    }
    return 0;
}

/* --- Python entry point ------------------------------------------------- */

static int pctx_init(PreimageCtx *pctx, uint32_t version, uint32_t locktime,
                     int32_t input_index, const char *source_txid,
                     uint32_t source_vout, uint32_t input_sequence,
                     int64_t source_satoshis,
                     PyObject *other_inputs_py, PyObject *outputs_py) {
    memset(pctx, 0, sizeof(*pctx));
    pctx->version = version;
    pctx->locktime = locktime;
    pctx->input_index = input_index;
    pctx->cur_vout = source_vout;
    pctx->cur_satoshis = source_satoshis;
    pctx->cur_sequence = input_sequence;
    pctx->outputs_list = outputs_py;
    pctx->n_outputs = PyList_GET_SIZE(outputs_py);

    if (hex_to_bytes_reversed(source_txid, pctx->cur_txid_le, 32) < 0) {
        PyErr_SetString(PyExc_ValueError, "invalid source_txid hex");
        return -1;
    }

    Py_ssize_t n_other = PyList_GET_SIZE(other_inputs_py);
    pctx->n_other = n_other;
    pctx->other_inputs = NULL;
    if (n_other > 0) {
        pctx->other_inputs = (PCtxInput *)calloc(n_other, sizeof(PCtxInput));
        if (!pctx->other_inputs) { PyErr_NoMemory(); return -1; }
    }

    Py_ssize_t total = n_other + 1;
    size_t prevouts_len = (size_t)total * 36;
    size_t seq_len = (size_t)total * 4;
    unsigned char *prevouts_buf = (unsigned char *)malloc(prevouts_len > 0 ? prevouts_len : 1);
    unsigned char *seq_buf = (unsigned char *)malloc(seq_len > 0 ? seq_len : 1);
    if (!prevouts_buf || !seq_buf) {
        free(prevouts_buf); free(seq_buf);
        free(pctx->other_inputs); pctx->other_inputs = NULL;
        PyErr_NoMemory(); return -1;
    }

    for (Py_ssize_t i = 0; i < n_other; i++) {
        const char *txid_hex;
        uint32_t vout, seq, sh;
        int64_t sats;
        const unsigned char *scr;
        Py_ssize_t scr_len;
        if (parse_input_tuple(PyList_GET_ITEM(other_inputs_py, i),
                &txid_hex, &vout, &scr, &scr_len, &sats, &seq, &sh) < 0) {
            free(prevouts_buf); free(seq_buf);
            free(pctx->other_inputs); pctx->other_inputs = NULL;
            return -1;
        }
        if (hex_to_bytes_reversed(txid_hex, pctx->other_inputs[i].txid_le, 32) < 0) {
            free(prevouts_buf); free(seq_buf);
            free(pctx->other_inputs); pctx->other_inputs = NULL;
            PyErr_SetString(PyExc_ValueError, "invalid txid hex in other_inputs");
            return -1;
        }
        pctx->other_inputs[i].vout = vout;
        pctx->other_inputs[i].script = scr;
        pctx->other_inputs[i].script_len = scr_len;
        pctx->other_inputs[i].satoshis = sats;
        pctx->other_inputs[i].sequence = seq;
        pctx->other_inputs[i].sighash = sh;
    }

    for (Py_ssize_t i = 0; i < total; i++) {
        const unsigned char *txid_le;
        uint32_t vout, seq;
        if (i == input_index) {
            txid_le = pctx->cur_txid_le;
            vout = pctx->cur_vout;
            seq = pctx->cur_sequence;
        } else {
            Py_ssize_t oi = (i < input_index) ? i : i - 1;
            txid_le = pctx->other_inputs[oi].txid_le;
            vout = pctx->other_inputs[oi].vout;
            seq = pctx->other_inputs[oi].sequence;
        }
        memcpy(prevouts_buf + i * 36, txid_le, 32);
        write_u32_le(prevouts_buf + i * 36 + 32, vout);
        write_u32_le(seq_buf + i * 4, seq);
    }

    hash256_var(prevouts_buf, prevouts_len, pctx->hash_prevouts);
    hash256_var(seq_buf, seq_len, pctx->hash_sequence);
    free(prevouts_buf); free(seq_buf);

    size_t total_out = 0;
    for (Py_ssize_t i = 0; i < pctx->n_outputs; i++) {
        PyObject *ob = PyList_GET_ITEM(outputs_py, i);
        if (!PyBytes_Check(ob)) {
            free(pctx->other_inputs); pctx->other_inputs = NULL;
            PyErr_SetString(PyExc_TypeError, "output must be bytes");
            return -1;
        }
        total_out += PyBytes_GET_SIZE(ob);
    }
    unsigned char *out_buf = (unsigned char *)malloc(total_out > 0 ? total_out : 1);
    if (!out_buf) {
        free(pctx->other_inputs); pctx->other_inputs = NULL;
        PyErr_NoMemory(); return -1;
    }
    size_t opos = 0;
    for (Py_ssize_t i = 0; i < pctx->n_outputs; i++) {
        PyObject *ob = PyList_GET_ITEM(outputs_py, i);
        Py_ssize_t olen = PyBytes_GET_SIZE(ob);
        memcpy(out_buf + opos, PyBytes_AS_STRING(ob), olen);
        opos += olen;
    }
    hash256_var(out_buf, total_out, pctx->hash_outputs);
    free(out_buf);

    return 0;
}

static void pctx_free(PreimageCtx *pctx) {
    free(pctx->other_inputs);
    pctx->other_inputs = NULL;
}

static PyObject *pyfn_spend_validate(PyObject *self, PyObject *args) {
    PyObject *unlock_chunks, *lock_chunks, *other_inputs_py, *outputs_py;
    int tx_version, source_output_index, input_index;
    unsigned int lock_time, input_sequence;
    long long source_satoshis;
    const char *source_txid;

    if (!PyArg_ParseTuple(args, "OOisiIiILOO",
            &unlock_chunks, &lock_chunks,
            &tx_version, &source_txid, &source_output_index,
            &lock_time, &input_index, &input_sequence,
            &source_satoshis,
            &other_inputs_py, &outputs_py))
        return NULL;

    if (!PyList_Check(unlock_chunks) || !PyList_Check(lock_chunks)) {
        PyErr_SetString(PyExc_TypeError, "chunks must be lists");
        return NULL;
    }
    if (!PyList_Check(other_inputs_py) || !PyList_Check(outputs_py)) {
        PyErr_SetString(PyExc_TypeError, "other_inputs and outputs must be lists");
        return NULL;
    }
    if (!ensure_context()) return NULL;

    VMState st;
    memset(&st, 0, sizeof(st));
    vms_init(&st.stack);
    vms_init(&st.alt_stack);
    ifs_init(&st.if_stack);
    st.unlock_chunks = unlock_chunks;
    st.lock_chunks = lock_chunks;
    st.program_counter = 0;
    st.context = VM_CTX_UNLOCK;
    st.last_code_separator = 0;
    st.tx_version = tx_version;
    st.source_txid = source_txid;
    st.source_output_index = source_output_index;

    if (pctx_init(&st.pctx, (uint32_t)tx_version, (uint32_t)lock_time,
                  (int32_t)input_index, source_txid,
                  (uint32_t)source_output_index, (uint32_t)input_sequence,
                  (int64_t)source_satoshis,
                  other_inputs_py, outputs_py) < 0) {
        vms_free(&st.stack);
        vms_free(&st.alt_stack);
        ifs_free(&st.if_stack);
        return NULL;
    }

    int result = vm_run(&st);

    pctx_free(&st.pctx);
    vms_free(&st.stack);
    vms_free(&st.alt_stack);
    ifs_free(&st.if_stack);

    if (result < 0) return NULL;
    Py_RETURN_TRUE;
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
    {"ecdsa_sign_with_k", pyfn_ecdsa_sign_with_k, METH_VARARGS,
     "ecdsa_sign_with_k(msg32, secret32, k32) -> bytes\n\n"
     "Create a DER-encoded ECDSA signature with a custom nonce k (low-S normalized)."},
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

    /* Phase 1: Script chunks */
    {"parse_script_chunks", pyfn_parse_script_chunks, METH_VARARGS,
     "parse_script_chunks(script_bytes) -> list[tuple[int, bytes|None]]\n\n"
     "Parse script bytes into (opcode, data) tuples."},
    {"serialize_script_chunks", pyfn_serialize_script_chunks, METH_VARARGS,
     "serialize_script_chunks(chunks) -> bytes\n\n"
     "Serialize (opcode, data) tuples to script bytes."},

    /* Phase 1: Merkle */
    {"merkle_compute_root", pyfn_merkle_compute_root, METH_VARARGS,
     "merkle_compute_root(txid_hex, path) -> str\n\n"
     "Compute merkle root from txid and path levels (simple paths only)."},
    {"merkle_hash_pair", pyfn_merkle_hash_pair, METH_VARARGS,
     "merkle_hash_pair(left_hex, right_hex) -> str\n\n"
     "Hash two 64-char hex strings: reverse(hash256(reverse(bytes(left+right))))."},

    /* Phase 1: Transaction */
    {"tx_from_bytes", pyfn_tx_from_bytes, METH_VARARGS,
     "tx_from_bytes(raw) -> dict\n\n"
     "Parse raw transaction bytes into a dict."},
    {"tx_to_bytes", pyfn_tx_to_bytes, METH_VARARGS,
     "tx_to_bytes(version, inputs, outputs, locktime) -> bytes\n\n"
     "Serialize transaction components to raw bytes."},
    {"tx_txid", pyfn_tx_txid, METH_VARARGS,
     "tx_txid(raw) -> str\n\n"
     "Compute txid (hash256 reversed hex) from raw tx bytes."},

    /* Phase 2: Preimage */
    {"tx_preimages", pyfn_tx_preimages, METH_VARARGS,
     "tx_preimages(version, locktime, inputs, outputs) -> list[bytes]\n\n"
     "Compute BIP-143 preimages for all inputs."},
    {"tx_preimage_otda", pyfn_tx_preimage_otda, METH_VARARGS,
     "tx_preimage_otda(input_index, version, locktime, inputs, outputs) -> bytes\n\n"
     "Compute OTDA preimage for a specific input."},

    /* Script VM */
    {"spend_validate", pyfn_spend_validate, METH_VARARGS,
     "spend_validate(unlock_chunks, lock_chunks, tx_version, source_txid, "
     "source_output_index, lock_time, input_index, input_sequence, "
     "source_satoshis, other_inputs, outputs) -> True\n\n"
     "Run script VM with CHECKSIG internalized in C. "
     "Raises RuntimeError on validation failure."},

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
