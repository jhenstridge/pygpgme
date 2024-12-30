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
#include "pygpgme.h"

static void
add_enum_value(PyObject *dict, const char *key, long value)
{
    PyObject *py_value = PyLong_FromLong(value);

    PyDict_SetItemString(dict, key, py_value);
    Py_DECREF(py_value);
}

static PyObject *
make_enum(PyObject *mod, const char *base_name, const char *name, PyObject *values)
{
    PyObject *enum_module, *base_class, *enum_name, *module_name, *kwnames;
    PyObject *args[4] = { NULL, };
    PyObject *enum_class;

    base_class = PyUnicode_FromString(base_name);
    enum_name = PyUnicode_FromString(name);
    module_name = PyUnicode_FromString("gpgme");
    kwnames = Py_BuildValue("(s)", "module");

    enum_module = PyImport_ImportModule("enum");
    args[0] = enum_module;
    args[1] = enum_name;
    args[2] = values;
    args[3] = module_name;

    enum_class = PyObject_VectorcallMethod(base_class, args, 3 + PY_VECTORCALL_ARGUMENTS_OFFSET, kwnames);

    Py_DECREF(enum_module);
    Py_DECREF(kwnames);
    Py_DECREF(module_name);
    Py_DECREF(enum_name);
    Py_DECREF(base_class);

    PyModule_AddObject(mod, name, enum_class);
    return enum_class;
}

void
pygpgme_add_constants (PyObject *mod)
{
    PyGpgmeModState *state = PyModule_GetState(mod);
    PyObject *values;

    /* gpgme_data_encoding_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_DATA_ENCODING_##name)
    CONST(NONE);
    CONST(BINARY);
    CONST(BASE64);
    CONST(ARMOR);
    state->DataEncoding_Type = make_enum(mod, "IntEnum", "DataEncoding", values);
    Py_DECREF(values);

    /* gpgme_pubkey_algo_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_PK_##name)
    CONST(RSA);
    CONST(RSA_E);
    CONST(RSA_S);
    CONST(ELG_E);
    CONST(DSA);
    CONST(ELG);
    CONST(ECDSA);
    CONST(ECDH);
    CONST(EDDSA);
    state->PubkeyAlgo_Type = make_enum(mod, "IntEnum", "PubkeyAlgo", values);
    Py_DECREF(values);

    /* gpgme_hash_algo_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_MD_##name)
    CONST(NONE);
    CONST(MD5);
    CONST(SHA1);
    CONST(RMD160);
    CONST(MD2);
    CONST(TIGER);
    CONST(HAVAL);
    CONST(SHA256);
    CONST(SHA384);
    CONST(SHA512);
    CONST(MD4);
    CONST(CRC32);
    CONST(CRC32_RFC1510);
    CONST(CRC24_RFC2440);
    state->HashAlgo_Type = make_enum(mod, "IntEnum", "HashAlgo", values);
    Py_DECREF(values);

    /* gpgme_sig_mode_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_SIG_MODE_##name)
    CONST(NORMAL);
    CONST(DETACH);
    CONST(CLEAR);
    state->SigMode_Type = make_enum(mod, "IntEnum", "SigMode", values);
    Py_DECREF(values);

    /* gpgme_validity_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_VALIDITY_##name)
    CONST(UNKNOWN);
    CONST(UNDEFINED);
    CONST(NEVER);
    CONST(MARGINAL);
    CONST(FULL);
    CONST(ULTIMATE);
    state->Validity_Type = make_enum(mod, "IntEnum", "Validity", values);
    Py_DECREF(values);

    /* gpgme_protocol_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_PROTOCOL_##name)
    CONST(OpenPGP);
    CONST(CMS);
    CONST(GPGCONF);
    CONST(ASSUAN);
    CONST(G13);
    CONST(UISERVER);
    CONST(SPAWN);
    CONST(DEFAULT);
    CONST(UNKNOWN);
    state->Protocol_Type = make_enum(mod, "IntEnum", "Protocol", values);
    Py_DECREF(values);

    /* gpgme_keylist_mode_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_KEYLIST_MODE_##name)
    CONST(LOCAL);
    CONST(EXTERN);
    CONST(SIGS);
    CONST(SIG_NOTATIONS);
    CONST(WITH_SECRET);
    CONST(WITH_TOFU);
    CONST(EPHEMERAL);
    CONST(VALIDATE);
    CONST(LOCATE);
#if GPGME_VERSION_NUMBER >= VER(1, 14, 0)
    CONST(WITH_KEYGRIP);
#endif
#if GPGME_VERSION_NUMBER >= VER(1, 18, 0)
    CONST(FORCE_EXTERN);
    CONST(LOCATE_EXTERNAL);
#endif
    state->KeylistMode_Type = make_enum(mod, "IntFlag", "KeylistMode", values);
    Py_DECREF(values);

    /* gpgme_pinentry_mode_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_PINENTRY_MODE_##name)
    CONST(DEFAULT);
    CONST(ASK);
    CONST(CANCEL);
    CONST(ERROR);
    CONST(LOOPBACK);
    state->PinentryMode_Type = make_enum(mod, "IntEnum", "PinentryMode", values);
    Py_DECREF(values);

    /* gpgme_export_mode_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_EXPORT_MODE_##name)
    CONST(EXTERN);
    CONST(MINIMAL);
    CONST(SECRET);
    CONST(RAW);
    CONST(PKCS12);
#if GPGME_VERSION_NUMBER >= VER(1, 14, 0)
    CONST(SSH);
#endif
#if GPGME_VERSION_NUMBER >= VER(1, 17, 0)
    CONST(SECRET_SUBKEY);
#endif
    state->ExportMode_Type = make_enum(mod, "IntFlag", "ExportMode", values);
    Py_DECREF(values);

    /* gpgme_sig_notation_flags_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_SIG_NOTATION_##name)
    CONST(HUMAN_READABLE);
    CONST(CRITICAL);
    state->SigNotationFlags_Type = make_enum(mod, "IntFlag", "SigNotationFlags", values);
    Py_DECREF(values);

    /* gpgme_status_code_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_STATUS_##name)
    CONST(EOF);
    CONST(ENTER);
    CONST(LEAVE);
    CONST(ABORT);
    CONST(GOODSIG);
    CONST(BADSIG);
    CONST(ERRSIG);
    CONST(BADARMOR);
    CONST(RSA_OR_IDEA);
    CONST(KEYEXPIRED);
    CONST(KEYREVOKED);
    CONST(TRUST_UNDEFINED);
    CONST(TRUST_NEVER);
    CONST(TRUST_MARGINAL);
    CONST(TRUST_FULLY);
    CONST(TRUST_ULTIMATE);
    CONST(SHM_INFO);
    CONST(SHM_GET);
    CONST(SHM_GET_BOOL);
    CONST(SHM_GET_HIDDEN);
    CONST(NEED_PASSPHRASE);
    CONST(VALIDSIG);
    CONST(SIG_ID);
    CONST(ENC_TO);
    CONST(NODATA);
    CONST(BAD_PASSPHRASE);
    CONST(NO_PUBKEY);
    CONST(NO_SECKEY);
    CONST(NEED_PASSPHRASE_SYM);
    CONST(DECRYPTION_FAILED);
    CONST(DECRYPTION_OKAY);
    CONST(MISSING_PASSPHRASE);
    CONST(GOOD_PASSPHRASE);
    CONST(GOODMDC);
    CONST(BADMDC);
    CONST(ERRMDC);
    CONST(IMPORTED);
    CONST(IMPORT_OK);
    CONST(IMPORT_PROBLEM);
    CONST(IMPORT_RES);
    CONST(FILE_START);
    CONST(FILE_DONE);
    CONST(FILE_ERROR);
    CONST(BEGIN_DECRYPTION);
    CONST(END_DECRYPTION);
    CONST(BEGIN_ENCRYPTION);
    CONST(END_ENCRYPTION);
    CONST(DELETE_PROBLEM);
    CONST(GET_BOOL);
    CONST(GET_LINE);
    CONST(GET_HIDDEN);
    CONST(GOT_IT);
    CONST(PROGRESS);
    CONST(SIG_CREATED);
    CONST(SESSION_KEY);
    CONST(NOTATION_NAME);
    CONST(NOTATION_DATA);
    CONST(POLICY_URL);
    CONST(BEGIN_STREAM);
    CONST(END_STREAM);
    CONST(KEY_CREATED);
    CONST(USERID_HINT);
    CONST(UNEXPECTED);
    CONST(INV_RECP);
    CONST(NO_RECP);
    CONST(ALREADY_SIGNED);
    CONST(SIGEXPIRED);
    CONST(EXPSIG);
    CONST(EXPKEYSIG);
    CONST(TRUNCATED);
    CONST(ERROR);
    CONST(NEWSIG);
    CONST(REVKEYSIG);
    CONST(SIG_SUBPACKET);
    CONST(NEED_PASSPHRASE_PIN);
    CONST(SC_OP_FAILURE);
    CONST(SC_OP_SUCCESS);
    CONST(CARDCTRL);
    CONST(BACKUP_KEY_CREATED);
    CONST(PKA_TRUST_BAD);
    CONST(PKA_TRUST_GOOD);
    CONST(PLAINTEXT);
    CONST(INV_SGNR);
    CONST(NO_SGNR);
    CONST(SUCCESS);
    CONST(DECRYPTION_INFO);
    CONST(PLAINTEXT_LENGTH);
    CONST(MOUNTPOINT);
    CONST(PINENTRY_LAUNCHED);
    CONST(ATTRIBUTE);
    CONST(BEGIN_SIGNING);
    CONST(KEY_NOT_CREATED);
    CONST(INQUIRE_MAXLEN);
    CONST(FAILURE);
    CONST(KEY_CONSIDERED);
    CONST(TOFU_USER);
    CONST(TOFU_STATS);
    CONST(TOFU_STATS_LONG);
    CONST(NOTATION_FLAGS);
    CONST(DECRYPTION_COMPLIANCE_MODE);
    CONST(VERIFICATION_COMPLIANCE_MODE);
#if GPGME_VERSION_NUMBER >= VER(1, 15, 0)
    CONST(CANCELED_BY_USER);
#endif
    state->Status_Type = make_enum(mod, "IntEnum", "Status", values);
    Py_DECREF(values);

    /* gpgme_encrypt_flags_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_ENCRYPT_##name)
    CONST(ALWAYS_TRUST);
    CONST(NO_ENCRYPT_TO);
    CONST(PREPARE);
    CONST(EXPECT_SIGN);
    CONST(NO_COMPRESS);
    CONST(SYMMETRIC);
    CONST(THROW_KEYIDS);
    CONST(WRAP);
    CONST(WANT_ADDRESS);
    state->EncryptFlags_Type = make_enum(mod, "IntFlag", "EncryptFlags", values);
    Py_DECREF(values);

    /* gpgme_sigsum_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_SIGSUM_##name)
    CONST(VALID);
    CONST(GREEN);
    CONST(RED);
    CONST(KEY_REVOKED);
    CONST(KEY_EXPIRED);
    CONST(SIG_EXPIRED);
    CONST(KEY_MISSING);
    CONST(CRL_MISSING);
    CONST(CRL_TOO_OLD);
    CONST(BAD_POLICY);
    CONST(SYS_ERROR);
    CONST(TOFU_CONFLICT);
    state->Sigsum_Type = make_enum(mod, "IntFlag", "Sigsum", values);
    Py_DECREF(values);

    /* import status */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_IMPORT_##name)
    CONST(NEW);
    CONST(UID);
    CONST(SIG);
    CONST(SUBKEY);
    CONST(SECRET);
    state->Import_Type = make_enum(mod, "IntFlag", "Import", values);
    Py_DECREF(values);

    /* delete flags */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPGME_DELETE_##name)
    CONST(ALLOW_SECRET);
    CONST(FORCE);
    state->Delete_Type = make_enum(mod, "IntFlag", "Delete", values);
    Py_DECREF(values);

    /* gpg_err_source_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPG_ERR_SOURCE_##name)
    CONST(UNKNOWN);
    CONST(GCRYPT);
    CONST(GPG);
    CONST(GPGSM);
    CONST(GPGAGENT);
    CONST(PINENTRY);
    CONST(SCD);
    CONST(GPGME);
    CONST(KEYBOX);
    CONST(KSBA);
    CONST(DIRMNGR);
    CONST(GSTI);
    CONST(GPA);
    CONST(KLEO);
    CONST(G13);
    CONST(ASSUAN);
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 42, 0)
    CONST(TPM2D);
#endif
    CONST(TLS);
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 47, 0)
    CONST(TKD);
#endif
    CONST(ANY);
    CONST(USER_1);
    CONST(USER_2);
    CONST(USER_3);
    CONST(USER_4);
    state->ErrSource_Type = make_enum(mod, "IntEnum", "ErrSource", values);
    Py_DECREF(values);

    /* gpg_err_code_t */
    values = PyDict_New();
#undef CONST
#define CONST(name) add_enum_value(values, #name, GPG_ERR_##name)
    CONST(NO_ERROR);
    CONST(GENERAL);
    CONST(UNKNOWN_PACKET);
    CONST(UNKNOWN_VERSION);
    CONST(PUBKEY_ALGO);
    CONST(DIGEST_ALGO);
    CONST(BAD_PUBKEY);
    CONST(BAD_SECKEY);
    CONST(BAD_SIGNATURE);
    CONST(NO_PUBKEY);
    CONST(CHECKSUM);
    CONST(BAD_PASSPHRASE);
    CONST(CIPHER_ALGO);
    CONST(KEYRING_OPEN);
    CONST(INV_PACKET);
    CONST(INV_ARMOR);
    CONST(NO_USER_ID);
    CONST(NO_SECKEY);
    CONST(WRONG_SECKEY);
    CONST(BAD_KEY);
    CONST(COMPR_ALGO);
    CONST(NO_PRIME);
    CONST(NO_ENCODING_METHOD);
    CONST(NO_ENCRYPTION_SCHEME);
    CONST(NO_SIGNATURE_SCHEME);
    CONST(INV_ATTR);
    CONST(NO_VALUE);
    CONST(NOT_FOUND);
    CONST(VALUE_NOT_FOUND);
    CONST(SYNTAX);
    CONST(BAD_MPI);
    CONST(INV_PASSPHRASE);
    CONST(SIG_CLASS);
    CONST(RESOURCE_LIMIT);
    CONST(INV_KEYRING);
    CONST(TRUSTDB);
    CONST(BAD_CERT);
    CONST(INV_USER_ID);
    CONST(UNEXPECTED);
    CONST(TIME_CONFLICT);
    CONST(KEYSERVER);
    CONST(WRONG_PUBKEY_ALGO);
    CONST(TRIBUTE_TO_D_A);
    CONST(WEAK_KEY);
    CONST(INV_KEYLEN);
    CONST(INV_ARG);
    CONST(BAD_URI);
    CONST(INV_URI);
    CONST(NETWORK);
    CONST(UNKNOWN_HOST);
    CONST(SELFTEST_FAILED);
    CONST(NOT_ENCRYPTED);
    CONST(NOT_PROCESSED);
    CONST(UNUSABLE_PUBKEY);
    CONST(UNUSABLE_SECKEY);
    CONST(INV_VALUE);
    CONST(BAD_CERT_CHAIN);
    CONST(MISSING_CERT);
    CONST(NO_DATA);
    CONST(BUG);
    CONST(NOT_SUPPORTED);
    CONST(INV_OP);
    CONST(TIMEOUT);
    CONST(INTERNAL);
    CONST(EOF_GCRYPT);
    CONST(INV_OBJ);
    CONST(TOO_SHORT);
    CONST(TOO_LARGE);
    CONST(NO_OBJ);
    CONST(NOT_IMPLEMENTED);
    CONST(CONFLICT);
    CONST(INV_CIPHER_MODE);
    CONST(INV_FLAG);
    CONST(INV_HANDLE);
    CONST(TRUNCATED);
    CONST(INCOMPLETE_LINE);
    CONST(INV_RESPONSE);
    CONST(NO_AGENT);
    CONST(AGENT);
    CONST(INV_DATA);
    CONST(ASSUAN_SERVER_FAULT);
    CONST(ASSUAN);
    CONST(INV_SESSION_KEY);
    CONST(INV_SEXP);
    CONST(UNSUPPORTED_ALGORITHM);
    CONST(NO_PIN_ENTRY);
    CONST(PIN_ENTRY);
    CONST(BAD_PIN);
    CONST(INV_NAME);
    CONST(BAD_DATA);
    CONST(INV_PARAMETER);
    CONST(WRONG_CARD);
    CONST(NO_DIRMNGR);
    CONST(DIRMNGR);
    CONST(CERT_REVOKED);
    CONST(NO_CRL_KNOWN);
    CONST(CRL_TOO_OLD);
    CONST(LINE_TOO_LONG);
    CONST(NOT_TRUSTED);
    CONST(CANCELED);
    CONST(BAD_CA_CERT);
    CONST(CERT_EXPIRED);
    CONST(CERT_TOO_YOUNG);
    CONST(UNSUPPORTED_CERT);
    CONST(UNKNOWN_SEXP);
    CONST(UNSUPPORTED_PROTECTION);
    CONST(CORRUPTED_PROTECTION);
    CONST(AMBIGUOUS_NAME);
    CONST(CARD);
    CONST(CARD_RESET);
    CONST(CARD_REMOVED);
    CONST(INV_CARD);
    CONST(CARD_NOT_PRESENT);
    CONST(NO_PKCS15_APP);
    CONST(NOT_CONFIRMED);
    CONST(CONFIGURATION);
    CONST(NO_POLICY_MATCH);
    CONST(INV_INDEX);
    CONST(INV_ID);
    CONST(NO_SCDAEMON);
    CONST(SCDAEMON);
    CONST(UNSUPPORTED_PROTOCOL);
    CONST(BAD_PIN_METHOD);
    CONST(CARD_NOT_INITIALIZED);
    CONST(UNSUPPORTED_OPERATION);
    CONST(WRONG_KEY_USAGE);
    CONST(NOTHING_FOUND);
    CONST(WRONG_BLOB_TYPE);
    CONST(MISSING_VALUE);
    CONST(HARDWARE);
    CONST(PIN_BLOCKED);
    CONST(USE_CONDITIONS);
    CONST(PIN_NOT_SYNCED);
    CONST(INV_CRL);
    CONST(BAD_BER);
    CONST(INV_BER);
    CONST(ELEMENT_NOT_FOUND);
    CONST(IDENTIFIER_NOT_FOUND);
    CONST(INV_TAG);
    CONST(INV_LENGTH);
    CONST(INV_KEYINFO);
    CONST(UNEXPECTED_TAG);
    CONST(NOT_DER_ENCODED);
    CONST(NO_CMS_OBJ);
    CONST(INV_CMS_OBJ);
    CONST(UNKNOWN_CMS_OBJ);
    CONST(UNSUPPORTED_CMS_OBJ);
    CONST(UNSUPPORTED_ENCODING);
    CONST(UNSUPPORTED_CMS_VERSION);
    CONST(UNKNOWN_ALGORITHM);
    CONST(INV_ENGINE);
    CONST(PUBKEY_NOT_TRUSTED);
    CONST(DECRYPT_FAILED);
    CONST(KEY_EXPIRED);
    CONST(SIG_EXPIRED);
    CONST(ENCODING_PROBLEM);
    CONST(INV_STATE);
    CONST(DUP_VALUE);
    CONST(MISSING_ACTION);
    CONST(MODULE_NOT_FOUND);
    CONST(INV_OID_STRING);
    CONST(INV_TIME);
    CONST(INV_CRL_OBJ);
    CONST(UNSUPPORTED_CRL_VERSION);
    CONST(INV_CERT_OBJ);
    CONST(UNKNOWN_NAME);
    CONST(LOCALE_PROBLEM);
    CONST(NOT_LOCKED);
    CONST(PROTOCOL_VIOLATION);
    CONST(INV_MAC);
    CONST(INV_REQUEST);
    CONST(UNKNOWN_EXTN);
    CONST(UNKNOWN_CRIT_EXTN);
    CONST(LOCKED);
    CONST(UNKNOWN_OPTION);
    CONST(UNKNOWN_COMMAND);
    CONST(NOT_OPERATIONAL);
    CONST(NO_PASSPHRASE);
    CONST(NO_PIN);
    CONST(NOT_ENABLED);
    CONST(NO_ENGINE);
    CONST(MISSING_KEY);
    CONST(TOO_MANY);
    CONST(LIMIT_REACHED);
    CONST(NOT_INITIALIZED);
    CONST(MISSING_ISSUER_CERT);
    CONST(NO_KEYSERVER);
    CONST(INV_CURVE);
    CONST(UNKNOWN_CURVE);
    CONST(DUP_KEY);
    CONST(AMBIGUOUS);
    CONST(NO_CRYPT_CTX);
    CONST(WRONG_CRYPT_CTX);
    CONST(BAD_CRYPT_CTX);
    CONST(CRYPT_CTX_CONFLICT);
    CONST(BROKEN_PUBKEY);
    CONST(BROKEN_SECKEY);
    CONST(MAC_ALGO);
    CONST(FULLY_CANCELED);
    CONST(UNFINISHED);
    CONST(BUFFER_TOO_SHORT);
    CONST(SEXP_INV_LEN_SPEC);
    CONST(SEXP_STRING_TOO_LONG);
    CONST(SEXP_UNMATCHED_PAREN);
    CONST(SEXP_NOT_CANONICAL);
    CONST(SEXP_BAD_CHARACTER);
    CONST(SEXP_BAD_QUOTATION);
    CONST(SEXP_ZERO_PREFIX);
    CONST(SEXP_NESTED_DH);
    CONST(SEXP_UNMATCHED_DH);
    CONST(SEXP_UNEXPECTED_PUNC);
    CONST(SEXP_BAD_HEX_CHAR);
    CONST(SEXP_ODD_HEX_NUMBERS);
    CONST(SEXP_BAD_OCT_CHAR);
    CONST(SUBKEYS_EXP_OR_REV);
    CONST(DB_CORRUPTED);
    CONST(SERVER_FAILED);
    CONST(NO_NAME);
    CONST(NO_KEY);
    CONST(LEGACY_KEY);
    CONST(REQUEST_TOO_SHORT);
    CONST(REQUEST_TOO_LONG);
    CONST(OBJ_TERM_STATE);
    CONST(NO_CERT_CHAIN);
    CONST(CERT_TOO_LARGE);
    CONST(INV_RECORD);
    CONST(BAD_MAC);
    CONST(UNEXPECTED_MSG);
    CONST(COMPR_FAILED);
    CONST(WOULD_WRAP);
    CONST(FATAL_ALERT);
    CONST(NO_CIPHER);
    CONST(MISSING_CLIENT_CERT);
    CONST(CLOSE_NOTIFY);
    CONST(TICKET_EXPIRED);
    CONST(BAD_TICKET);
    CONST(UNKNOWN_IDENTITY);
    CONST(BAD_HS_CERT);
    CONST(BAD_HS_CERT_REQ);
    CONST(BAD_HS_CERT_VER);
    CONST(BAD_HS_CHANGE_CIPHER);
    CONST(BAD_HS_CLIENT_HELLO);
    CONST(BAD_HS_SERVER_HELLO);
    CONST(BAD_HS_SERVER_HELLO_DONE);
    CONST(BAD_HS_FINISHED);
    CONST(BAD_HS_SERVER_KEX);
    CONST(BAD_HS_CLIENT_KEX);
    CONST(BOGUS_STRING);
    CONST(FORBIDDEN);
    CONST(KEY_DISABLED);
    CONST(KEY_ON_CARD);
    CONST(INV_LOCK_OBJ);
    CONST(TRUE);
    CONST(FALSE);
    CONST(ASS_GENERAL);
    CONST(ASS_ACCEPT_FAILED);
    CONST(ASS_CONNECT_FAILED);
    CONST(ASS_INV_RESPONSE);
    CONST(ASS_INV_VALUE);
    CONST(ASS_INCOMPLETE_LINE);
    CONST(ASS_LINE_TOO_LONG);
    CONST(ASS_NESTED_COMMANDS);
    CONST(ASS_NO_DATA_CB);
    CONST(ASS_NO_INQUIRE_CB);
    CONST(ASS_NOT_A_SERVER);
    CONST(ASS_NOT_A_CLIENT);
    CONST(ASS_SERVER_START);
    CONST(ASS_READ_ERROR);
    CONST(ASS_WRITE_ERROR);
    CONST(ASS_TOO_MUCH_DATA);
    CONST(ASS_UNEXPECTED_CMD);
    CONST(ASS_UNKNOWN_CMD);
    CONST(ASS_SYNTAX);
    CONST(ASS_CANCELED);
    CONST(ASS_NO_INPUT);
    CONST(ASS_NO_OUTPUT);
    CONST(ASS_PARAMETER);
    CONST(ASS_UNKNOWN_INQUIRE);
    CONST(ENGINE_TOO_OLD);
    CONST(WINDOW_TOO_SMALL);
    CONST(WINDOW_TOO_LARGE);
    CONST(MISSING_ENVVAR);
    CONST(USER_ID_EXISTS);
    CONST(NAME_EXISTS);
    CONST(DUP_NAME);
    CONST(TOO_YOUNG);
    CONST(TOO_OLD);
    CONST(UNKNOWN_FLAG);
    CONST(INV_ORDER);
    CONST(ALREADY_FETCHED);
    CONST(TRY_LATER);
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 27, 0)
    CONST(WRONG_NAME);
#endif
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 36, 0)
    CONST(NO_AUTH);
    CONST(BAD_AUTH);
#endif
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 37, 0)
    CONST(NO_KEYBOXD);
    CONST(KEYBOXD);
    CONST(NO_SERVICE);
    CONST(SERVICE);
#endif
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 47, 0)
    CONST(BAD_PUK);
    CONST(NO_RESET_CODE);
    CONST(BAD_RESET_CODE);
#endif
    CONST(SYSTEM_BUG);
    CONST(DNS_UNKNOWN);
    CONST(DNS_SECTION);
    CONST(DNS_ADDRESS);
    CONST(DNS_NO_QUERY);
    CONST(DNS_NO_ANSWER);
    CONST(DNS_CLOSED);
    CONST(DNS_VERIFY);
    CONST(DNS_TIMEOUT);
    CONST(LDAP_GENERAL);
    CONST(LDAP_ATTR_GENERAL);
    CONST(LDAP_NAME_GENERAL);
    CONST(LDAP_SECURITY_GENERAL);
    CONST(LDAP_SERVICE_GENERAL);
    CONST(LDAP_UPDATE_GENERAL);
    CONST(LDAP_E_GENERAL);
    CONST(LDAP_X_GENERAL);
    CONST(LDAP_OTHER_GENERAL);
    CONST(LDAP_X_CONNECTING);
    CONST(LDAP_REFERRAL_LIMIT);
    CONST(LDAP_CLIENT_LOOP);
    CONST(LDAP_NO_RESULTS);
    CONST(LDAP_CONTROL_NOT_FOUND);
    CONST(LDAP_NOT_SUPPORTED);
    CONST(LDAP_CONNECT);
    CONST(LDAP_NO_MEMORY);
    CONST(LDAP_PARAM);
    CONST(LDAP_USER_CANCELLED);
    CONST(LDAP_FILTER);
    CONST(LDAP_AUTH_UNKNOWN);
    CONST(LDAP_TIMEOUT);
    CONST(LDAP_DECODING);
    CONST(LDAP_ENCODING);
    CONST(LDAP_LOCAL);
    CONST(LDAP_SERVER_DOWN);
    CONST(LDAP_SUCCESS);
    CONST(LDAP_OPERATIONS);
    CONST(LDAP_PROTOCOL);
    CONST(LDAP_TIMELIMIT);
    CONST(LDAP_SIZELIMIT);
    CONST(LDAP_COMPARE_FALSE);
    CONST(LDAP_COMPARE_TRUE);
    CONST(LDAP_UNSUPPORTED_AUTH);
    CONST(LDAP_STRONG_AUTH_RQRD);
    CONST(LDAP_PARTIAL_RESULTS);
    CONST(LDAP_REFERRAL);
    CONST(LDAP_ADMINLIMIT);
    CONST(LDAP_UNAVAIL_CRIT_EXTN);
    CONST(LDAP_CONFIDENT_RQRD);
    CONST(LDAP_SASL_BIND_INPROG);
    CONST(LDAP_NO_SUCH_ATTRIBUTE);
    CONST(LDAP_UNDEFINED_TYPE);
    CONST(LDAP_BAD_MATCHING);
    CONST(LDAP_CONST_VIOLATION);
    CONST(LDAP_TYPE_VALUE_EXISTS);
    CONST(LDAP_INV_SYNTAX);
    CONST(LDAP_NO_SUCH_OBJ);
    CONST(LDAP_ALIAS_PROBLEM);
    CONST(LDAP_INV_DN_SYNTAX);
    CONST(LDAP_IS_LEAF);
    CONST(LDAP_ALIAS_DEREF);
    CONST(LDAP_X_PROXY_AUTH_FAIL);
    CONST(LDAP_BAD_AUTH);
    CONST(LDAP_INV_CREDENTIALS);
    CONST(LDAP_INSUFFICIENT_ACC);
    CONST(LDAP_BUSY);
    CONST(LDAP_UNAVAILABLE);
    CONST(LDAP_UNWILL_TO_PERFORM);
    CONST(LDAP_LOOP_DETECT);
    CONST(LDAP_NAMING_VIOLATION);
    CONST(LDAP_OBJ_CLS_VIOLATION);
    CONST(LDAP_NOT_ALLOW_NONLEAF);
    CONST(LDAP_NOT_ALLOW_ON_RDN);
    CONST(LDAP_ALREADY_EXISTS);
    CONST(LDAP_NO_OBJ_CLASS_MODS);
    CONST(LDAP_RESULTS_TOO_LARGE);
    CONST(LDAP_AFFECTS_MULT_DSAS);
    CONST(LDAP_VLV);
    CONST(LDAP_OTHER);
    CONST(LDAP_CUP_RESOURCE_LIMIT);
    CONST(LDAP_CUP_SEC_VIOLATION);
    CONST(LDAP_CUP_INV_DATA);
    CONST(LDAP_CUP_UNSUP_SCHEME);
    CONST(LDAP_CUP_RELOAD);
    CONST(LDAP_CANCELLED);
    CONST(LDAP_NO_SUCH_OPERATION);
    CONST(LDAP_TOO_LATE);
    CONST(LDAP_CANNOT_CANCEL);
    CONST(LDAP_ASSERTION_FAILED);
    CONST(LDAP_PROX_AUTH_DENIED);
    CONST(USER_1);
    CONST(USER_2);
    CONST(USER_3);
    CONST(USER_4);
    CONST(USER_5);
    CONST(USER_6);
    CONST(USER_7);
    CONST(USER_8);
    CONST(USER_9);
    CONST(USER_10);
    CONST(USER_11);
    CONST(USER_12);
    CONST(USER_13);
    CONST(USER_14);
    CONST(USER_15);
    CONST(USER_16);
#if GPG_ERROR_VERSION_NUMBER >= VER(1, 37, 0)
    CONST(SQL_OK);
    CONST(SQL_ERROR);
    CONST(SQL_INTERNAL);
    CONST(SQL_PERM);
    CONST(SQL_ABORT);
    CONST(SQL_BUSY);
    CONST(SQL_LOCKED);
    CONST(SQL_NOMEM);
    CONST(SQL_READONLY);
    CONST(SQL_INTERRUPT);
    CONST(SQL_IOERR);
    CONST(SQL_CORRUPT);
    CONST(SQL_NOTFOUND);
    CONST(SQL_FULL);
    CONST(SQL_CANTOPEN);
    CONST(SQL_PROTOCOL);
    CONST(SQL_EMPTY);
    CONST(SQL_SCHEMA);
    CONST(SQL_TOOBIG);
    CONST(SQL_CONSTRAINT);
    CONST(SQL_MISMATCH);
    CONST(SQL_MISUSE);
    CONST(SQL_NOLFS);
    CONST(SQL_AUTH);
    CONST(SQL_FORMAT);
    CONST(SQL_RANGE);
    CONST(SQL_NOTADB);
    CONST(SQL_NOTICE);
    CONST(SQL_WARNING);
    CONST(SQL_ROW);
    CONST(SQL_DONE);
#endif
    CONST(MISSING_ERRNO);
    CONST(UNKNOWN_ERRNO);
    CONST(EOF);
    CONST(E2BIG);
    CONST(EACCES);
    CONST(EADDRINUSE);
    CONST(EADDRNOTAVAIL);
    CONST(EADV);
    CONST(EAFNOSUPPORT);
    CONST(EAGAIN);
    CONST(EALREADY);
    CONST(EAUTH);
    CONST(EBACKGROUND);
    CONST(EBADE);
    CONST(EBADF);
    CONST(EBADFD);
    CONST(EBADMSG);
    CONST(EBADR);
    CONST(EBADRPC);
    CONST(EBADRQC);
    CONST(EBADSLT);
    CONST(EBFONT);
    CONST(EBUSY);
    CONST(ECANCELED);
    CONST(ECHILD);
    CONST(ECHRNG);
    CONST(ECOMM);
    CONST(ECONNABORTED);
    CONST(ECONNREFUSED);
    CONST(ECONNRESET);
    CONST(ED);
    CONST(EDEADLK);
    CONST(EDEADLOCK);
    CONST(EDESTADDRREQ);
    CONST(EDIED);
    CONST(EDOM);
    CONST(EDOTDOT);
    CONST(EDQUOT);
    CONST(EEXIST);
    CONST(EFAULT);
    CONST(EFBIG);
    CONST(EFTYPE);
    CONST(EGRATUITOUS);
    CONST(EGREGIOUS);
    CONST(EHOSTDOWN);
    CONST(EHOSTUNREACH);
    CONST(EIDRM);
    CONST(EIEIO);
    CONST(EILSEQ);
    CONST(EINPROGRESS);
    CONST(EINTR);
    CONST(EINVAL);
    CONST(EIO);
    CONST(EISCONN);
    CONST(EISDIR);
    CONST(EISNAM);
    CONST(EL2HLT);
    CONST(EL2NSYNC);
    CONST(EL3HLT);
    CONST(EL3RST);
    CONST(ELIBACC);
    CONST(ELIBBAD);
    CONST(ELIBEXEC);
    CONST(ELIBMAX);
    CONST(ELIBSCN);
    CONST(ELNRNG);
    CONST(ELOOP);
    CONST(EMEDIUMTYPE);
    CONST(EMFILE);
    CONST(EMLINK);
    CONST(EMSGSIZE);
    CONST(EMULTIHOP);
    CONST(ENAMETOOLONG);
    CONST(ENAVAIL);
    CONST(ENEEDAUTH);
    CONST(ENETDOWN);
    CONST(ENETRESET);
    CONST(ENETUNREACH);
    CONST(ENFILE);
    CONST(ENOANO);
    CONST(ENOBUFS);
    CONST(ENOCSI);
    CONST(ENODATA);
    CONST(ENODEV);
    CONST(ENOENT);
    CONST(ENOEXEC);
    CONST(ENOLCK);
    CONST(ENOLINK);
    CONST(ENOMEDIUM);
    CONST(ENOMEM);
    CONST(ENOMSG);
    CONST(ENONET);
    CONST(ENOPKG);
    CONST(ENOPROTOOPT);
    CONST(ENOSPC);
    CONST(ENOSR);
    CONST(ENOSTR);
    CONST(ENOSYS);
    CONST(ENOTBLK);
    CONST(ENOTCONN);
    CONST(ENOTDIR);
    CONST(ENOTEMPTY);
    CONST(ENOTNAM);
    CONST(ENOTSOCK);
    CONST(ENOTSUP);
    CONST(ENOTTY);
    CONST(ENOTUNIQ);
    CONST(ENXIO);
    CONST(EOPNOTSUPP);
    CONST(EOVERFLOW);
    CONST(EPERM);
    CONST(EPFNOSUPPORT);
    CONST(EPIPE);
    CONST(EPROCLIM);
    CONST(EPROCUNAVAIL);
    CONST(EPROGMISMATCH);
    CONST(EPROGUNAVAIL);
    CONST(EPROTO);
    CONST(EPROTONOSUPPORT);
    CONST(EPROTOTYPE);
    CONST(ERANGE);
    CONST(EREMCHG);
    CONST(EREMOTE);
    CONST(EREMOTEIO);
    CONST(ERESTART);
    CONST(EROFS);
    CONST(ERPCMISMATCH);
    CONST(ESHUTDOWN);
    CONST(ESOCKTNOSUPPORT);
    CONST(ESPIPE);
    CONST(ESRCH);
    CONST(ESRMNT);
    CONST(ESTALE);
    CONST(ESTRPIPE);
    CONST(ETIME);
    CONST(ETIMEDOUT);
    CONST(ETOOMANYREFS);
    CONST(ETXTBSY);
    CONST(EUCLEAN);
    CONST(EUNATCH);
    CONST(EUSERS);
    CONST(EWOULDBLOCK);
    CONST(EXDEV);
    CONST(EXFULL);
    state->ErrCode_Type = make_enum(mod, "IntEnum", "ErrCode", values);
    Py_DECREF(values);
}

PyObject *
pygpgme_enum_value_new (PyObject *type, long value)
{
    PyObject *int_value, *enum_value;
    PyObject *args[2] = { NULL, };

    int_value = PyLong_FromLong(value);
    args[1] = int_value;
    enum_value = PyObject_Vectorcall(type, &args[1], 1 + PY_VECTORCALL_ARGUMENTS_OFFSET, NULL);
    if (!enum_value && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
        Py_INCREF(int_value);
        enum_value = int_value;
    }
    Py_DECREF(int_value);
    return enum_value;
}
