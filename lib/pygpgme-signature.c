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
#include <gpgme.h>
#include <structmember.h>

static void
pygpgme_newsig_dealloc(PyGpgmeNewSignature *self)
{
    Py_XDECREF(self->type);
    Py_XDECREF(self->pubkey_algo);
    Py_XDECREF(self->hash_algo);
    Py_XDECREF(self->timestamp);
    Py_XDECREF(self->fpr);
    Py_XDECREF(self->sig_class);
    PyObject_Del(self);
}

static PyMemberDef pygpgme_newsig_members[] = {
    { "type", T_OBJECT, offsetof(PyGpgmeNewSignature, type), READONLY},
    { "pubkey_algo", T_OBJECT, offsetof(PyGpgmeNewSignature, pubkey_algo), READONLY},
    { "hash_algo", T_OBJECT, offsetof(PyGpgmeNewSignature, hash_algo), READONLY},
    { "timestamp", T_OBJECT, offsetof(PyGpgmeNewSignature, timestamp), READONLY},
    { "fpr", T_OBJECT, offsetof(PyGpgmeNewSignature, fpr), READONLY},
    { "sig_class", T_OBJECT, offsetof(PyGpgmeNewSignature, sig_class), READONLY},
    { NULL, 0, 0, 0}
};

static const char pygpgme_newsig_doc[] =
    "Data for newly created signatures.\n"
    "\n"
    "Instances of this class are usually obtained as the result value of\n"
    ":meth:`Context.sign` or :meth:`Context.encrypt_sign`.\n";

static PyType_Slot pygpgme_newsig_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_newsig_dealloc },
    { Py_tp_members, pygpgme_newsig_members },
    { Py_tp_doc, (void *)pygpgme_newsig_doc },
    { 0, NULL },
};

PyType_Spec pygpgme_newsig_spec = {
    .name = "gpgme.NewSignature",
    .basicsize = sizeof(PyGpgmeNewSignature),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_newsig_slots,
};

PyObject *
pygpgme_newsiglist_new(PyGpgmeModState *state, gpgme_new_signature_t siglist)
{
    PyObject *list;
    gpgme_new_signature_t sig;

    list = PyList_New(0);
    for (sig = siglist; sig != NULL; sig = sig->next) {
        PyGpgmeNewSignature *item = PyObject_New(PyGpgmeNewSignature,
                                                 (PyTypeObject *)state->PyGpgmeNewSignature_Type);
        if (item == NULL) {
            Py_DECREF(list);
            return NULL;
        }
        item->type = pygpgme_enum_value_new(PyGpgmeSigMode_Type, sig->type);
        item->pubkey_algo = pygpgme_enum_value_new(PyGpgmePubkeyAlgo_Type, sig->pubkey_algo);
        item->hash_algo = pygpgme_enum_value_new(PyGpgmeHashAlgo_Type, sig->hash_algo);
        item->timestamp = PyLong_FromLong(sig->timestamp);
        if (sig->fpr) {
            item->fpr = PyUnicode_DecodeASCII(sig->fpr, strlen(sig->fpr),
                                              "replace");
        } else {
            Py_INCREF(Py_None);
            item->fpr = Py_None;
        }
        item->sig_class = PyLong_FromLong(sig->sig_class);
        if (PyErr_Occurred()) {
            Py_DECREF(item);
            Py_DECREF(list);
            return NULL;
        }
        PyList_Append(list, (PyObject *)item);
        Py_DECREF(item);
    }
    return list;
}

static void
pygpgme_sig_dealloc(PyGpgmeSignature *self)
{
    Py_XDECREF(self->summary);
    Py_XDECREF(self->fpr);
    Py_XDECREF(self->status);
    Py_XDECREF(self->notations);
    Py_XDECREF(self->timestamp);
    Py_XDECREF(self->exp_timestamp);
    Py_XDECREF(self->wrong_key_usage);
    Py_XDECREF(self->validity);
    Py_XDECREF(self->validity_reason);
    Py_XDECREF(self->pubkey_algo);
    Py_XDECREF(self->hash_algo);
    PyObject_Del(self);
}

static const char pygpgme_sig_summary_doc[] =
    "A bit array encoded as an integer containing general information about\n"
    "about the signature.\n"
    "\n"
    "Combine this value with one of the :class:`Sigsum` constants using\n"
    "bitwise AND.\n";

static const char pygpgme_sig_fpr_doc[] =
    "Fingerprint string";

static const char pygpgme_sig_status_doc[] =
    "If an error occurred during verification (for example because the\n"
    "signature is not valid) then this attribute contains a corresponding\n"
    ":class:`GpgmeError` instance. Otherwise it is ``None``.\n";

static const char pygpgme_sig_notations_doc[] =
    "A list of notation data represented by :class:`SigNotation` objects.";

static const char pygpgme_sig_timestamp_doc[] =
    "Creation timestamp of the signature.";

static const char pygpgme_sig_exp_timestamp_doc[] =
    "Expiration timestamp of the signature, or 0 if the signature does\n"
    "not expire.";

static const char pygpgme_sig_wrong_key_usage_doc[] =
    "True if the key was not used according to its policy.";

static const char pygpgme_sig_validity_doc[] =
    "Validity of the signature. See :attr:`Signature.validity_reason`.";

static const char pygpgme_sig_validity_reason_doc[] =
    "If a signature is not valid this may provide a reason why. See\n"
    ":attr:`Signature.validity`.";

static const char pygpgme_sig_pubkey_algo_doc[] =
    "The public key algorithm of the signature, as a :class:`PubkeyAlgo`\n"
    "constant.";

static const char pygpgme_sig_hash_algo_doc[] =
    "The hash algorithm of the signature, as a :class:`HashAlgo` constant.";

static PyMemberDef pygpgme_sig_members[] = {
    { "summary", T_OBJECT, offsetof(PyGpgmeSignature, summary), READONLY,
      pygpgme_sig_summary_doc },
    { "fpr", T_OBJECT, offsetof(PyGpgmeSignature, fpr), READONLY,
      pygpgme_sig_fpr_doc },
    { "status", T_OBJECT, offsetof(PyGpgmeSignature, status), READONLY,
      pygpgme_sig_status_doc },
    { "notations", T_OBJECT, offsetof(PyGpgmeSignature, notations), READONLY,
      pygpgme_sig_notations_doc },
    { "timestamp", T_OBJECT, offsetof(PyGpgmeSignature, timestamp), READONLY,
      pygpgme_sig_timestamp_doc },
    { "exp_timestamp", T_OBJECT,
      offsetof(PyGpgmeSignature, exp_timestamp), READONLY,
      pygpgme_sig_exp_timestamp_doc },
    { "wrong_key_usage", T_OBJECT,
      offsetof(PyGpgmeSignature, wrong_key_usage), READONLY,
      pygpgme_sig_wrong_key_usage_doc },
    { "validity", T_OBJECT, offsetof(PyGpgmeSignature, validity), READONLY,
      pygpgme_sig_validity_doc },
    { "validity_reason", T_OBJECT,
      offsetof(PyGpgmeSignature, validity_reason), READONLY,
      pygpgme_sig_validity_reason_doc },
    { "pubkey_algo", T_OBJECT, offsetof(PyGpgmeSignature, pubkey_algo), READONLY,
      pygpgme_sig_pubkey_algo_doc },
    { "hash_algo", T_OBJECT, offsetof(PyGpgmeSignature, hash_algo), READONLY,
      pygpgme_sig_hash_algo_doc },
    { NULL, 0, 0, 0 },
};

static const char pygpgme_sig_doc[] =
    "Signature verification data.\n"
    "\n"
    "Instances of this class are usually obtained as the return value of\n"
    ":meth:`Context.verify` or :meth:`Context.decrypt_verify`.\n";

static PyType_Slot pygpgme_sig_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_sig_dealloc },
    { Py_tp_members, pygpgme_sig_members },
    { Py_tp_doc, (void *)pygpgme_sig_doc },
    { 0, NULL },
};

PyType_Spec pygpgme_sig_spec = {
    .name = "gpgme.Signature",
    .basicsize = sizeof(PyGpgmeSignature),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_sig_slots,
};

PyObject *
pygpgme_siglist_new(PyGpgmeModState *state, gpgme_signature_t siglist)
{
    PyObject *list;
    gpgme_signature_t sig;

    list = PyList_New(0);
    for (sig = siglist; sig != NULL; sig = sig->next) {
        PyGpgmeSignature *item = PyObject_New(PyGpgmeSignature,
                                              (PyTypeObject *)state->PyGpgmeSignature_Type);
        if (item == NULL) {
            Py_DECREF(list);
            return NULL;
        }
        item->summary = pygpgme_enum_value_new(PyGpgmeSigsum_Type, sig->summary);
        if (sig->fpr) {
            item->fpr = PyUnicode_DecodeASCII(sig->fpr, strlen(sig->fpr),
                                              "replace");
        } else {
            Py_INCREF(Py_None);
            item->fpr = Py_None;
        }
        item->status = pygpgme_error_object(state, sig->status);
        item->notations = pygpgme_sig_notation_list_new(state, sig->notations);
        item->timestamp = PyLong_FromLong(sig->timestamp);
        item->exp_timestamp = PyLong_FromLong(sig->exp_timestamp);
        item->wrong_key_usage = PyBool_FromLong(sig->wrong_key_usage);
        item->validity = pygpgme_enum_value_new(PyGpgmeValidity_Type, sig->validity);
        item->validity_reason = pygpgme_error_object(state, sig->validity_reason);
        item->pubkey_algo = pygpgme_enum_value_new(PyGpgmePubkeyAlgo_Type, sig->pubkey_algo);
        item->hash_algo = pygpgme_enum_value_new(PyGpgmeHashAlgo_Type, sig->hash_algo);
        if (PyErr_Occurred()) {
            Py_DECREF(item);
            Py_DECREF(list);
            return NULL;
        }
        PyList_Append(list, (PyObject *)item);
        Py_DECREF(item);
    }
    return list;
}

static int
pygpgme_sig_notation_init(PyGpgmeSigNotation *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "name", "value", "flags", NULL };
    PyObject *name = NULL, *value = NULL;
    gpgme_sig_notation_flags_t flags = GPGME_SIG_NOTATION_HUMAN_READABLE;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|I", kwlist,
                                     &name, &value, &flags))
        return -1;

    if (!(name == Py_None || PyUnicode_Check(name))) {
        PyErr_SetString(PyExc_TypeError, "name must be a str or None");
        return -1;
    }
    if ((flags & GPGME_SIG_NOTATION_HUMAN_READABLE) != 0) {
        if (!PyUnicode_Check(value)) {
            PyErr_SetString(PyExc_TypeError, "value must be a str for human readable notations");
            return -1;
        }
    } else {
        if (!PyBytes_Check(value)) {
            PyErr_SetString(PyExc_TypeError, "value must be bytes for non-human readable notations");
            return -1;
        }
    }

    Py_XDECREF(self->name);
    Py_INCREF(name);
    self->name = name;
    Py_XDECREF(self->value);
    Py_INCREF(value);
    self->value = value;
    self->flags = flags;

    return 0;
}

static void
pygpgme_sig_notation_dealloc(PyGpgmeSigNotation *self)
{
    Py_XDECREF(self->name);
    Py_XDECREF(self->value);
}

static Py_ssize_t
pygpgme_sig_notation_length(PyGpgmeSigNotation *self)
{
    return 2;
}

static PyObject *
pygpgme_sig_notation_item(PyGpgmeSigNotation *self, Py_ssize_t index)
{
    switch (index) {
    case 0:
        Py_INCREF(self->name);
        return self->name;
    case 1:
        Py_INCREF(self->value);
        return self->value;
    default:
        PyErr_SetString(PyExc_IndexError, "index out of range");
        return NULL;
    }
}

static PyMemberDef pygpgme_sig_notation_members[] = {
    { "name", T_OBJECT, offsetof(PyGpgmeSigNotation, name), READONLY},
    { "value", T_OBJECT, offsetof(PyGpgmeSigNotation, value), READONLY},
    { NULL, 0, 0, 0}
};

static PyObject *
pygpgme_sig_notation_get_flags(PyGpgmeSigNotation *self)
{
    return pygpgme_enum_value_new(PyGpgmeSigNotationFlags_Type, self->flags);
}

static PyObject *
pygpgme_sig_notation_get_human_readable(PyGpgmeSigNotation *self)
{
    return PyBool_FromLong((self->flags & GPGME_SIG_NOTATION_HUMAN_READABLE) != 0);
}

static PyObject *
pygpgme_sig_notation_get_critical(PyGpgmeSigNotation *self)
{
    return PyBool_FromLong((self->flags & GPGME_SIG_NOTATION_CRITICAL) != 0);
}

static PyGetSetDef pygpgme_sig_notation_getsets[] = {
    { "flags", (getter)pygpgme_sig_notation_get_flags, NULL, NULL },
    { "human_readable", (getter)pygpgme_sig_notation_get_human_readable, NULL, NULL },
    { "critical", (getter)pygpgme_sig_notation_get_critical, NULL, NULL },
    { NULL, (getter)0, (setter)0 }
};

static PyType_Slot pygpgme_sig_notation_slots[] = {
    { Py_tp_init, pygpgme_sig_notation_init },
    { Py_tp_dealloc, pygpgme_sig_notation_dealloc },
    { Py_tp_members, pygpgme_sig_notation_members },
    { Py_tp_getset, pygpgme_sig_notation_getsets },
    { Py_sq_length, pygpgme_sig_notation_length },
    { Py_sq_item, pygpgme_sig_notation_item },
    { 0, NULL },
};

PyType_Spec pygpgme_sig_notation_spec = {
    .name = "gpgme.SigNotation",
    .basicsize = sizeof(PyGpgmeSigNotation),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_sig_notation_slots,
};

PyObject *
pygpgme_sig_notation_list_new(PyGpgmeModState *state, gpgme_sig_notation_t notations)
{
    gpgme_sig_notation_t not;
    PyObject *list;

    list = PyList_New(0);
    for (not = notations; not != NULL; not = not->next) {
        PyGpgmeSigNotation *item = PyObject_New(PyGpgmeSigNotation,
                                                (PyTypeObject *)state->PyGpgmeSigNotation_Type);
        if (item == NULL) {
            Py_DECREF(list);
            return NULL;
        }

        if (not->name != NULL) {
            item->name = PyUnicode_DecodeUTF8(
                not->name, not->name_len, "replace");
        } else {
            Py_INCREF(Py_None);
            item->name = Py_None;
        }
        if ((not->flags & GPGME_SIG_NOTATION_HUMAN_READABLE) != 0) {
            item->value = PyUnicode_DecodeUTF8(
                not->value, not->value_len, "replace");
        } else {
            item->value = PyBytes_FromStringAndSize(not->value, not->value_len);
        }
        item->flags = not->flags;
        PyList_Append(list, (PyObject *)item);
        Py_DECREF(item);
    }
    return list;
}
