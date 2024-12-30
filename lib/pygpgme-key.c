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
#include <Python.h>
#include "pygpgme.h"

static void
pygpgme_subkey_dealloc(PyGpgmeSubkey *self)
{
    self->subkey = NULL;
    Py_XDECREF(self->parent);
    self->parent = NULL;
    PyObject_Del(self);
}

static PyObject *
pygpgme_subkey_get_revoked(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->revoked);
}

static PyObject *
pygpgme_subkey_get_expired(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->expired);
}

static PyObject *
pygpgme_subkey_get_disabled(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->disabled);
}

static PyObject *
pygpgme_subkey_get_invalid(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->invalid);
}

static PyObject *
pygpgme_subkey_get_can_encrypt(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->can_encrypt);
}

static PyObject *
pygpgme_subkey_get_can_sign(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->can_sign);
}

static PyObject *
pygpgme_subkey_get_can_certify(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->can_certify);
}

static PyObject *
pygpgme_subkey_get_secret(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->secret);
}

static PyObject *
pygpgme_subkey_get_can_authenticate(PyGpgmeSubkey *self)
{
    return PyBool_FromLong(self->subkey->can_authenticate);
}

static PyObject *
pygpgme_subkey_get_pubkey_algo(PyGpgmeSubkey *self)
{
    return pygpgme_enum_value_new(PyGpgmePubkeyAlgo_Type, self->subkey->pubkey_algo);
}

static PyObject *
pygpgme_subkey_get_length(PyGpgmeSubkey *self)
{
    return PyLong_FromLong(self->subkey->length);
}

static PyObject *
pygpgme_subkey_get_keyid(PyGpgmeSubkey *self)
{
    if (self->subkey->keyid)
        return PyUnicode_DecodeASCII(self->subkey->keyid,
                                     strlen(self->subkey->keyid), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_subkey_get_fpr(PyGpgmeSubkey *self)
{
    if (self->subkey->fpr)
        return PyUnicode_DecodeASCII(self->subkey->fpr,
                                     strlen(self->subkey->fpr), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_subkey_get_timestamp(PyGpgmeSubkey *self)
{
    return PyLong_FromLong(self->subkey->timestamp);
}

static PyObject *
pygpgme_subkey_get_expires(PyGpgmeSubkey *self)
{
    return PyLong_FromLong(self->subkey->expires);
}

static PyGetSetDef pygpgme_subkey_getsets[] = {
    { "revoked", (getter)pygpgme_subkey_get_revoked },
    { "expired", (getter)pygpgme_subkey_get_expired },
    { "disabled", (getter)pygpgme_subkey_get_disabled },
    { "invalid", (getter)pygpgme_subkey_get_invalid },
    { "can_encrypt", (getter)pygpgme_subkey_get_can_encrypt },
    { "can_sign", (getter)pygpgme_subkey_get_can_sign },
    { "can_certify", (getter)pygpgme_subkey_get_can_certify },
    { "secret", (getter)pygpgme_subkey_get_secret },
    { "can_authenticate", (getter)pygpgme_subkey_get_can_authenticate },
    { "pubkey_algo", (getter)pygpgme_subkey_get_pubkey_algo },
    { "length", (getter)pygpgme_subkey_get_length },
    { "keyid", (getter)pygpgme_subkey_get_keyid },
    { "fpr", (getter)pygpgme_subkey_get_fpr },
    { "timestamp", (getter)pygpgme_subkey_get_timestamp },
    { "expires", (getter)pygpgme_subkey_get_expires },
    { NULL, (getter)0, (setter)0 }
};

static PyType_Slot pygpgme_subkey_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_subkey_dealloc },
    { Py_tp_getset, pygpgme_subkey_getsets },
    { 0, NULL },
};

PyType_Spec pygpgme_subkey_spec = {
    .name = "gpgme.Subkey",
    .basicsize = sizeof(PyGpgmeSubkey),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_subkey_slots,
};

static void
pygpgme_key_sig_dealloc(PyGpgmeKeySig *self)
{
    self->key_sig = NULL;
    Py_XDECREF(self->parent);
    self->parent = NULL;
    PyObject_Del(self);
}

static PyObject *
pygpgme_key_sig_get_revoked(PyGpgmeKeySig *self)
{
    return PyBool_FromLong(self->key_sig->revoked);
}

static PyObject *
pygpgme_key_sig_get_expired(PyGpgmeKeySig *self)
{
    return PyBool_FromLong(self->key_sig->expired);
}

static PyObject *
pygpgme_key_sig_get_invalid(PyGpgmeKeySig *self)
{
    return PyBool_FromLong(self->key_sig->invalid);
}

static PyObject *
pygpgme_key_sig_get_exportable(PyGpgmeKeySig *self)
{
    return PyBool_FromLong(self->key_sig->exportable);
}

static PyObject *
pygpgme_key_sig_get_pubkey_algo(PyGpgmeKeySig *self)
{
    return pygpgme_enum_value_new(PyGpgmePubkeyAlgo_Type, self->key_sig->pubkey_algo);
}

static PyObject *
pygpgme_key_sig_get_keyid(PyGpgmeKeySig *self)
{
    if (self->key_sig->keyid)
        return PyUnicode_DecodeASCII(self->key_sig->keyid,
                                     strlen(self->key_sig->keyid), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_key_sig_get_timestamp(PyGpgmeKeySig *self)
{
    return PyLong_FromLong(self->key_sig->timestamp);
}

static PyObject *
pygpgme_key_sig_get_expires(PyGpgmeKeySig *self)
{
    return PyLong_FromLong(self->key_sig->expires);
}

static PyObject *
pygpgme_key_sig_get_status(PyGpgmeKeySig *self)
{
    return pygpgme_error_object(self->key_sig->status);
}

static PyObject *
pygpgme_key_sig_get_uid(PyGpgmeKeySig *self)
{
    if (self->key_sig->uid)
        return PyUnicode_DecodeUTF8(self->key_sig->uid,
                                    strlen(self->key_sig->uid), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_key_sig_get_name(PyGpgmeKeySig *self)
{
    if (self->key_sig->name)
        return PyUnicode_DecodeUTF8(self->key_sig->name,
                                    strlen(self->key_sig->name), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_key_sig_get_email(PyGpgmeKeySig *self)
{
    if (self->key_sig->email)
        return PyUnicode_DecodeUTF8(self->key_sig->email,
                                    strlen(self->key_sig->email), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_key_sig_get_comment(PyGpgmeKeySig *self)
{
    if (self->key_sig->comment)
        return PyUnicode_DecodeUTF8(self->key_sig->comment,
                                    strlen(self->key_sig->comment), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_key_sig_get_sig_class(PyGpgmeKeySig *self)
{
    return PyLong_FromLong(self->key_sig->sig_class);
}

static PyGetSetDef pygpgme_key_sig_getsets[] = {
    { "revoked", (getter)pygpgme_key_sig_get_revoked },
    { "expired", (getter)pygpgme_key_sig_get_expired },
    { "invalid", (getter)pygpgme_key_sig_get_invalid },
    { "exportable", (getter)pygpgme_key_sig_get_exportable },
    { "pubkey_algo", (getter)pygpgme_key_sig_get_pubkey_algo },
    { "keyid", (getter)pygpgme_key_sig_get_keyid },
    { "timestamp", (getter)pygpgme_key_sig_get_timestamp },
    { "expires", (getter)pygpgme_key_sig_get_expires },
    { "status", (getter)pygpgme_key_sig_get_status },
    { "uid", (getter)pygpgme_key_sig_get_uid },
    { "name", (getter)pygpgme_key_sig_get_name },
    { "email", (getter)pygpgme_key_sig_get_email },
    { "comment", (getter)pygpgme_key_sig_get_comment },
    { "sig_class", (getter)pygpgme_key_sig_get_sig_class },
    { NULL, (getter)0, (setter)0 }
};

static PyType_Slot pygpgme_key_sig_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_key_sig_dealloc },
    { Py_tp_getset, pygpgme_key_sig_getsets },
    { 0, NULL },
};

PyType_Spec pygpgme_key_sig_spec = {
    .name = "gpgme.KeySig",
    .basicsize = sizeof(PyGpgmeKeySig),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_key_sig_slots,
};

static void
pygpgme_user_id_dealloc(PyGpgmeUserId *self)
{
    self->user_id = NULL;
    Py_XDECREF(self->parent);
    self->parent = NULL;
    PyObject_Del(self);
}

static PyObject *
pygpgme_user_id_get_revoked(PyGpgmeUserId *self)
{
    return PyBool_FromLong(self->user_id->revoked);
}

static PyObject *
pygpgme_user_id_get_invalid(PyGpgmeUserId *self)
{
    return PyBool_FromLong(self->user_id->invalid);
}

static PyObject *
pygpgme_user_id_get_validity(PyGpgmeUserId *self)
{
    return pygpgme_enum_value_new(PyGpgmeValidity_Type, self->user_id->validity);
}

static PyObject *
pygpgme_user_id_get_uid(PyGpgmeUserId *self)
{
    if (self->user_id->uid)
        return PyUnicode_DecodeUTF8(self->user_id->uid,
                                    strlen(self->user_id->uid), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_user_id_get_name(PyGpgmeUserId *self)
{
    if (self->user_id->name)
        return PyUnicode_DecodeUTF8(self->user_id->name,
                                    strlen(self->user_id->name), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_user_id_get_email(PyGpgmeUserId *self)
{
    if (self->user_id->email)
        return PyUnicode_DecodeUTF8(self->user_id->email,
                                    strlen(self->user_id->email), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_user_id_get_comment(PyGpgmeUserId *self)
{
    if (self->user_id->comment)
        return PyUnicode_DecodeUTF8(self->user_id->comment,
                                    strlen(self->user_id->comment), "replace");
    else
        Py_RETURN_NONE;
}

static PyObject *
pygpgme_user_id_get_signatures(PyGpgmeUserId *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *ret;
    gpgme_key_sig_t sig;

    ret = PyList_New(0);
    if (ret == NULL)
        return NULL;
    for (sig = self->user_id->signatures; sig != NULL; sig = sig->next) {
        PyGpgmeKeySig *item;

        item = PyObject_New(PyGpgmeKeySig, (PyTypeObject *)state->PyGpgmeKeySig_Type);
        if (item == NULL) {
            Py_DECREF(ret);
            return NULL;
        }
        item->key_sig = sig;
        Py_INCREF(self);
        item->parent = (PyObject *)self;
        PyList_Append(ret, (PyObject *)item);
        Py_DECREF(item);
    }
    return ret;
}

static PyGetSetDef pygpgme_user_id_getsets[] = {
    { "revoked", (getter)pygpgme_user_id_get_revoked },
    { "invalid", (getter)pygpgme_user_id_get_invalid },
    { "validity", (getter)pygpgme_user_id_get_validity },
    { "uid", (getter)pygpgme_user_id_get_uid },
    { "name", (getter)pygpgme_user_id_get_name },
    { "email", (getter)pygpgme_user_id_get_email },
    { "comment", (getter)pygpgme_user_id_get_comment },
    { "signatures", (getter)pygpgme_user_id_get_signatures },
    { NULL, (getter)0, (setter)0 }
};

static PyType_Slot pygpgme_user_id_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_user_id_dealloc },
    { Py_tp_getset, pygpgme_user_id_getsets },
    { 0, NULL },
};

PyType_Spec pygpgme_user_id_spec = {
    .name = "gpgme.UserId",
    .basicsize = sizeof(PyGpgmeUserId),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_user_id_slots,
};

static void
pygpgme_key_dealloc(PyGpgmeKey *self)
{
    gpgme_key_unref(self->key);
    self->key = NULL;
    PyObject_Del(self);
}

static const char pygpgme_key_revoked_doc[] =
    "True if the key has been revoked.";

static PyObject *
pygpgme_key_get_revoked(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->revoked);
}

static const char pygpgme_key_expired_doc[] =
    "True if the key has expired.";

static PyObject *
pygpgme_key_get_expired(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->expired);
}

static const char pygpgme_key_disabled_doc[] =
    "True if the key is disabled.";

static PyObject *
pygpgme_key_get_disabled(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->disabled);
}

static const char pygpgme_key_invalid_doc[] =
    "True if the key is invalid.\n"
    "\n"
    "This might have several reasons. For example, for the S/MIME backend\n"
    "it will be set during key listing if the key could not be validated\n"
    "due to a missing certificates or unmatched policies.\n";

static PyObject *
pygpgme_key_get_invalid(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->invalid);
}

static const char pygpgme_key_can_encrypt_doc[] =
    "True if the key (i.e. one of its subkeys) can be used for encryption.";

static PyObject *
pygpgme_key_get_can_encrypt(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->can_encrypt);
}

static const char pygpgme_key_can_sign_doc[] =
    "True if the key (i.e. one of its subkeys) can be used to create signatures.";

static PyObject *
pygpgme_key_get_can_sign(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->can_sign);
}

static const char pygpgme_key_can_certify_doc[] =
    "True if the key (i.e. one of its subkeys) can be used to create key\n"
    "certificates.";

static PyObject *
pygpgme_key_get_can_certify(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->can_certify);
}

static const char pygpgme_key_secret_doc[] =
    "True if the key is a secret key.\n"
    "\n"
    "Note that this will always be true even if the corresponding subkey\n"
    "flag may be false (offline/stub keys). This is only set if a listing\n"
    "of secret keys has been requested or if :data:`KeylistMode.WITH_SECRET`\n"
    "is active.\n";

static PyObject *
pygpgme_key_get_secret(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->secret);
}

static const char pygpgme_key_can_authenticate_doc[] =
    "True if the key (i.e. one of its subkeys) can be used for authentication.";

static PyObject *
pygpgme_key_get_can_authenticate(PyGpgmeKey *self)
{
    return PyBool_FromLong(self->key->can_authenticate);
}

static const char pygpgme_key_protocol_doc[] =
    "The protocol supported by this key. See the :class:`Protocol` constants.";

static PyObject *
pygpgme_key_get_protocol(PyGpgmeKey *self)
{
    return pygpgme_enum_value_new(PyGpgmeProtocol_Type, self->key->protocol);
}

static const char pygpgme_key_issuer_serial_doc[] =
    "If :attr:`Key.protocol` is :data:`Protocol.CMS` then this is the\n"
    "issuer serial.";

static PyObject *
pygpgme_key_get_issuer_serial(PyGpgmeKey *self)
{
    if (self->key->issuer_serial)
        /* Haven't tested this, so perhaps it should be UTF8 */
        return PyUnicode_DecodeASCII(self->key->issuer_serial,
                                     strlen(self->key->issuer_serial),
                                     "replace");
    else
        Py_RETURN_NONE;
}

static const char pygpgme_key_issuer_name_doc[] =
    "If :attr:`Key.protocol` is :data:`Protocol.CMS` then this is the\n"
    "issuer name.";

static PyObject *
pygpgme_key_get_issuer_name(PyGpgmeKey *self)
{
    if (self->key->issuer_name)
        return PyUnicode_DecodeUTF8(self->key->issuer_name,
                                    strlen(self->key->issuer_name),
                                    "replace");
    else
        Py_RETURN_NONE;
}

static const char pygpgme_key_chain_id_doc[] =
    "If :attr:`Key.protocol` is :data:`Protocol.CMS` then this is the\n"
    "chain ID, which can be used to built the certificate chain.";

static PyObject *
pygpgme_key_get_chain_id(PyGpgmeKey *self)
{
    if (self->key->chain_id)
        /* Haven't tested this, so perhaps it should be UTF8 */
        return PyUnicode_DecodeASCII(self->key->chain_id,
                                     strlen(self->key->chain_id), "replace");
    else
        Py_RETURN_NONE;
}

static const char pygpgme_key_owner_trust_doc[] =
    "If :attr:`Key.protocol` is :data:`Protocol.OpenPGP` then this is\n"
    "the owner trust.";

static PyObject *
pygpgme_key_get_owner_trust(PyGpgmeKey *self)
{
    return pygpgme_enum_value_new(PyGpgmeValidity_Type, self->key->owner_trust);
}

static const char pygpgme_key_subkeys_doc[] =
    "List of the key's subkeys as instances of :class:`Subkey`.\n"
    "\n"
    "The first subkey in the list is the primary key and usually available.\n";

static PyObject *
pygpgme_key_get_subkeys(PyGpgmeKey *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *ret;
    gpgme_subkey_t subkey;

    ret = PyList_New(0);
    if (ret == NULL)
        return NULL;
    for (subkey = self->key->subkeys; subkey != NULL; subkey = subkey->next) {
        PyGpgmeSubkey *item;

        item = PyObject_New(PyGpgmeSubkey, (PyTypeObject *)state->PyGpgmeSubkey_Type);
        if (item == NULL) {
            Py_DECREF(ret);
            return NULL;
        }
        item->subkey = subkey;
        Py_INCREF(self);
        item->parent = (PyObject *)self;
        PyList_Append(ret, (PyObject *)item);
        Py_DECREF(item);
    }
    return ret;
}

static const char pygpgme_key_uids_doc[] =
    "List of the key's user IDs as instances of :class:`UserId`.\n"
    "\n"
    "The first user ID in the list is the main (or primary) user ID.\n";

static PyObject *
pygpgme_key_get_uids(PyGpgmeKey *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *ret;
    gpgme_user_id_t uid;

    ret = PyList_New(0);
    if (ret == NULL)
        return NULL;
    for (uid = self->key->uids; uid != NULL; uid = uid->next) {
        PyGpgmeUserId *item;

        item = PyObject_New(PyGpgmeUserId, (PyTypeObject *)state->PyGpgmeUserId_Type);
        if (item == NULL) {
            Py_DECREF(ret);
            return NULL;
        }
        item->user_id = uid;
        Py_INCREF(self);
        item->parent = (PyObject *)self;
        PyList_Append(ret, (PyObject *)item);
        Py_DECREF(item);
    }
    return ret;
}

static const char pygpgme_key_keylist_mode_doc[] =
    "The keylist mode that was active when the key was retrieved.\n"
    "\n"
    "See :attr:`Context.keylist_mode`.\n";

static PyObject *
pygpgme_key_get_keylist_mode(PyGpgmeKey *self)
{
    return pygpgme_enum_value_new(PyGpgmeKeylistMode_Type, self->key->keylist_mode);
}

static PyGetSetDef pygpgme_key_getsets[] = {
    { "revoked", (getter)pygpgme_key_get_revoked, NULL,
      pygpgme_key_revoked_doc },
    { "expired", (getter)pygpgme_key_get_expired, NULL,
      pygpgme_key_expired_doc },
    { "disabled", (getter)pygpgme_key_get_disabled, NULL,
      pygpgme_key_disabled_doc },
    { "invalid", (getter)pygpgme_key_get_invalid, NULL,
      pygpgme_key_invalid_doc },
    { "can_encrypt", (getter)pygpgme_key_get_can_encrypt, NULL,
      pygpgme_key_can_encrypt_doc },
    { "can_sign", (getter)pygpgme_key_get_can_sign, NULL,
      pygpgme_key_can_sign_doc },
    { "can_certify", (getter)pygpgme_key_get_can_certify, NULL,
      pygpgme_key_can_certify_doc },
    { "secret", (getter)pygpgme_key_get_secret, NULL,
      pygpgme_key_secret_doc },
    { "can_authenticate", (getter)pygpgme_key_get_can_authenticate, NULL,
      pygpgme_key_can_authenticate_doc },
    { "protocol", (getter)pygpgme_key_get_protocol, NULL,
      pygpgme_key_protocol_doc },
    { "issuer_serial", (getter)pygpgme_key_get_issuer_serial, NULL,
      pygpgme_key_issuer_serial_doc },
    { "issuer_name", (getter)pygpgme_key_get_issuer_name, NULL,
      pygpgme_key_issuer_name_doc },
    { "chain_id", (getter)pygpgme_key_get_chain_id, NULL,
      pygpgme_key_chain_id_doc },
    { "owner_trust", (getter)pygpgme_key_get_owner_trust, NULL,
      pygpgme_key_owner_trust_doc },
    { "subkeys", (getter)pygpgme_key_get_subkeys, NULL,
      pygpgme_key_subkeys_doc },
    { "uids", (getter)pygpgme_key_get_uids, NULL,
      pygpgme_key_uids_doc },
    { "keylist_mode", (getter)pygpgme_key_get_keylist_mode, NULL,
      pygpgme_key_keylist_mode_doc },
    { NULL, (getter)0, (setter)0 }
};

static PyType_Slot pygpgme_key_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_key_dealloc },
    { Py_tp_getset, pygpgme_key_getsets },
    { 0, NULL },
};

PyType_Spec pygpgme_key_spec = {
    .name = "gpgme.Key",
    .basicsize = sizeof(PyGpgmeKey),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_key_slots,
};

PyObject *
pygpgme_key_new(PyGpgmeModState *state, gpgme_key_t key)
{
    PyGpgmeKey *self;

    self = PyObject_New(PyGpgmeKey, (PyTypeObject *)state->PyGpgmeKey_Type);
    if (self == NULL)
        return NULL;

    gpgme_key_ref(key);
    self->key = key;
    return (PyObject *)self;
}
