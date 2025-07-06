/* -*- mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
    pygpgme - a Python wrapper for the gpgme library
    Copyright (C) 2006  James Henstridge

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef PYGPGME_H
#define PYGPGME_H

#define PY_SSIZE_T_CLEAN 1
#include <Python.h>
#include <gpgme.h>

#define HIDDEN __attribute__((visibility("hidden")))

#define VER(major, minor, micro) ((major << 16) | (minor << 8) | micro)

typedef struct {
    PyObject_HEAD
    gpgme_ctx_t ctx;

    PyThread_type_lock mutex;
    PyThreadState *tstate;

    PyObject *passphrase_cb;
    PyObject *progress_cb;
} PyGpgmeContext;

typedef struct {
    PyObject_HEAD
    PyObject *protocol;
    PyObject *file_name;
    PyObject *version;
    PyObject *req_version;
    PyObject *home_dir;
} PyGpgmeEngineInfo;

typedef struct {
    PyObject_HEAD
    gpgme_key_t key;
} PyGpgmeKey;

typedef struct {
    PyObject_HEAD
    gpgme_subkey_t subkey;
    PyObject *parent;
} PyGpgmeSubkey;

typedef struct {
    PyObject_HEAD
    gpgme_user_id_t user_id;
    PyObject *parent;
} PyGpgmeUserId;

typedef struct {
    PyObject_HEAD
    gpgme_key_sig_t key_sig;
    PyObject *parent;
} PyGpgmeKeySig;

typedef struct {
    PyObject_HEAD
    PyObject *type;
    PyObject *pubkey_algo;
    PyObject *hash_algo;
    PyObject *timestamp;
    PyObject *fpr;
    PyObject *sig_class;
} PyGpgmeNewSignature;

typedef struct {
    PyObject_HEAD
    PyObject *summary;
    PyObject *fpr;
    PyObject *status;
    PyObject *notations;
    PyObject *timestamp;
    PyObject *exp_timestamp;
    PyObject *wrong_key_usage;
    PyObject *validity;
    PyObject *validity_reason;
    PyObject *pubkey_algo;
    PyObject *hash_algo;
} PyGpgmeSignature;

typedef struct {
    PyObject_HEAD
    PyObject *name;
    PyObject *value;
    gpgme_sig_notation_flags_t flags;
} PyGpgmeSigNotation;

typedef struct {
    PyObject_HEAD
    PyObject *considered;
    PyObject *no_user_id;
    PyObject *imported;
    PyObject *imported_rsa;
    PyObject *unchanged;
    PyObject *new_user_ids;
    PyObject *new_sub_keys;
    PyObject *new_signatures;
    PyObject *new_revocations;
    PyObject *secret_read;
    PyObject *secret_imported;
    PyObject *secret_unchanged;
    PyObject *skipped_new_keys;
    PyObject *not_imported;
    PyObject *imports;
} PyGpgmeImportResult;

typedef struct {
    PyObject_HEAD
    PyObject *primary;
    PyObject *sub;
    PyObject *fpr;
} PyGpgmeGenkeyResult;

typedef struct {
    PyObject_HEAD
    PyGpgmeContext *ctx;
} PyGpgmeKeyIter;

extern HIDDEN PyType_Spec pygpgme_context_spec;
extern HIDDEN PyType_Spec pygpgme_engine_info_spec;
extern HIDDEN PyType_Spec pygpgme_key_spec;
extern HIDDEN PyType_Spec pygpgme_subkey_spec;
extern HIDDEN PyType_Spec pygpgme_user_id_spec;
extern HIDDEN PyType_Spec pygpgme_key_sig_spec;
extern HIDDEN PyType_Spec pygpgme_keyiter_spec;
extern HIDDEN PyType_Spec pygpgme_newsig_spec;
extern HIDDEN PyType_Spec pygpgme_sig_spec;
extern HIDDEN PyType_Spec pygpgme_sig_notation_spec;
extern HIDDEN PyType_Spec pygpgme_import_result_spec;
extern HIDDEN PyType_Spec pygpgme_genkey_result_spec;

typedef struct {
    PyTypeObject *Context_Type;
    PyTypeObject *EngineInfo_Type;
    PyTypeObject *Key_Type;
    PyTypeObject *Subkey_Type;
    PyTypeObject *UserId_Type;
    PyTypeObject *KeySig_Type;
    PyTypeObject *KeyIter_Type;
    PyTypeObject *NewSignature_Type;
    PyTypeObject *Signature_Type;
    PyTypeObject *SigNotation_Type;
    PyTypeObject *ImportResult_Type;
    PyTypeObject *GenkeyResult_Type;

    /* enumerations and flags */
    PyObject *DataEncoding_Type;
    PyObject *PubkeyAlgo_Type;
    PyObject *HashAlgo_Type;
    PyObject *SigMode_Type;
    PyObject *Validity_Type;
    PyObject *Protocol_Type;
    PyObject *KeylistMode_Type;
    PyObject *PinentryMode_Type;
    PyObject *ExportMode_Type;
    PyObject *SigNotationFlags_Type;
    PyObject *Status_Type;
    PyObject *EncryptFlags_Type;
    PyObject *Sigsum_Type;
    PyObject *Import_Type;
    PyObject *Delete_Type;
    PyObject *ErrSource_Type;
    PyObject *ErrCode_Type;

    PyObject *pygpgme_error;
} PyGpgmeModState;

HIDDEN int           pygpgme_check_error    (PyGpgmeModState *state,
                                             gpgme_error_t err);
HIDDEN PyObject     *pygpgme_error_object   (PyGpgmeModState *state,
                                             gpgme_error_t err);
HIDDEN gpgme_error_t pygpgme_check_pyerror  (PyGpgmeModState *state);
HIDDEN int           pygpgme_no_constructor (PyObject *self, PyObject *args,
                                             PyObject *kwargs);

HIDDEN PyObject     *pygpgme_engine_info_list_new(PyGpgmeModState *state,
                                                  gpgme_engine_info_t info);
HIDDEN int           pygpgme_data_new       (PyGpgmeModState *state,
                                             gpgme_data_t *dh, PyObject *fp,
                                             PyGpgmeContext *ctx);
HIDDEN PyObject     *pygpgme_key_new        (PyGpgmeModState *state,
                                             gpgme_key_t key);
HIDDEN PyObject     *pygpgme_newsiglist_new (PyGpgmeModState *state,
                                             gpgme_new_signature_t siglist);
HIDDEN PyObject     *pygpgme_siglist_new    (PyGpgmeModState *state,
                                             gpgme_signature_t siglist);
HIDDEN PyObject     *pygpgme_sig_notation_list_new (PyGpgmeModState *state,
                                                    gpgme_sig_notation_t notations);
HIDDEN PyObject     *pygpgme_import_result  (PyGpgmeModState *state,
                                             gpgme_ctx_t ctx);
HIDDEN PyObject     *pygpgme_genkey_result  (PyGpgmeModState *state,
                                             gpgme_ctx_t ctx);

HIDDEN void          pygpgme_add_constants  (PyObject *mod);
HIDDEN PyObject     *pygpgme_enum_value_new (PyObject *type, long value);

#endif
