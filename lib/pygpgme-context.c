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
#include <assert.h>

static void
begin_allow_threads(PyGpgmeContext *self)
{
    PyThreadState *tstate;

    tstate = PyEval_SaveThread();
    PyThread_acquire_lock(self->mutex, WAIT_LOCK);
    assert(self->tstate == NULL);
    self->tstate = tstate;
}

static void
end_allow_threads(PyGpgmeContext *self)
{
    assert(self->tstate != NULL);
    PyEval_RestoreThread(self->tstate);
    self->tstate = NULL;
    PyThread_release_lock(self->mutex);
}

static void
lock_context(PyGpgmeContext *self)
{
    Py_BEGIN_ALLOW_THREADS;
    PyThread_acquire_lock(self->mutex, WAIT_LOCK);
    Py_END_ALLOW_THREADS;
}

static void
unlock_context(PyGpgmeContext *self)
{
    PyThread_release_lock(self->mutex);
}

static gpgme_error_t
pygpgme_passphrase_cb(void *hook, const char *uid_hint,
                      const char *passphrase_info, int prev_was_bad,
                      int fd)
{
    PyGpgmeContext *self = hook;
    PyGpgmeModState *state;
    PyObject *ret;
    gpgme_error_t err;

    assert(self->tstate != NULL);
    PyEval_RestoreThread(self->tstate);
    state = PyType_GetModuleState(Py_TYPE(self));
    ret = PyObject_CallFunction(self->passphrase_cb, "zzii",
                                uid_hint, passphrase_info,
                                prev_was_bad, fd);
    err = pygpgme_check_pyerror(state);
    Py_XDECREF(ret);
    self->tstate = PyEval_SaveThread();
    return err;
}

static void
pygpgme_progress_cb(void *hook, const char *what, int type,
                    int current, int total)
{
    PyGpgmeContext *self = hook;
    PyObject *ret;

    assert(self->tstate != NULL);
    PyEval_RestoreThread(self->tstate);
    ret = PyObject_CallFunction(self->progress_cb, "ziii", what, type, current, total);
    PyErr_Clear();
    Py_XDECREF(ret);
    self->tstate = PyEval_SaveThread();
}

static void
pygpgme_context_dealloc(PyGpgmeContext *self)
{
    if (self->ctx) {
        gpgme_release(self->ctx);
    }
    self->ctx = NULL;
    PyThread_free_lock(self->mutex);
    Py_XDECREF(self->passphrase_cb);
    Py_XDECREF(self->progress_cb);
    PyObject_Del(self);
}

static PyObject *
pygpgme_context_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PyGpgmeContext *self;

    self = (PyGpgmeContext *)type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }

    self->mutex = PyThread_allocate_lock();
    if (!self->mutex) {
        PyErr_NoMemory();
        type->tp_free(self);
        return NULL;
    }

    return (PyObject *)self;
}

static int
pygpgme_context_init(PyGpgmeContext *self, PyObject *args, PyObject *kwargs)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    static char *kwlist[] = { NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "", kwlist))
        return -1;

    if (self->ctx != NULL) {
        PyErr_SetString(PyExc_ValueError, "context already initialised");
        return -1;
    }

    if (pygpgme_check_error(state, gpgme_new(&self->ctx)))
        return -1;

    return 0;
}

static const char pygpgme_context_protocol_doc[] =
    "The encryption system for this context (one of the :class:`Protocol` constants).";

static PyObject *
pygpgme_context_get_protocol(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_protocol_t protocol;

    lock_context(self);
    protocol = gpgme_get_protocol(self->ctx);
    unlock_context(self);

    return pygpgme_enum_value_new(state->Protocol_Type, protocol);
}

static int
pygpgme_context_set_protocol(PyGpgmeContext *self, PyObject *value)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_protocol_t protocol;
    gpgme_error_t err;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    protocol = PyLong_AsLong(value);
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    err = gpgme_set_protocol(self->ctx, protocol);
    unlock_context(self);

    if (pygpgme_check_error(state, err))
        return -1;

    return 0;
}

static const char pygpgme_context_armor_doc[] =
    "Whether encrypted data should be ASCII-armored or not.\n"
    "\n"
    "Used by :meth:`encrypt`, meth:`encrypt_sign`, and :meth:`sign`.";

static PyObject *
pygpgme_context_get_armor(PyGpgmeContext *self)
{
    int armor;

    lock_context(self);
    armor = gpgme_get_armor(self->ctx);
    unlock_context(self);

    return PyBool_FromLong(armor);
}

static int
pygpgme_context_set_armor(PyGpgmeContext *self, PyObject *value)
{
    int armor;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    armor = PyLong_AsLong(value) != 0;
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    gpgme_set_armor(self->ctx, armor);
    unlock_context(self);

    return 0;
}

static const char pygpgme_context_textmode_doc[] =
    "Whether text mode is enabled.";

static PyObject *
pygpgme_context_get_textmode(PyGpgmeContext *self)
{
    int textmode;

    lock_context(self);
    textmode = gpgme_get_textmode(self->ctx);
    unlock_context(self);

    return PyBool_FromLong(textmode);
}

static int
pygpgme_context_set_textmode(PyGpgmeContext *self, PyObject *value)
{
    int textmode;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    textmode = PyLong_AsLong(value) != 0;
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    gpgme_set_textmode(self->ctx, textmode);
    unlock_context(self);
    return 0;
}

static const char pygpgme_context_offline_doc[] =
    "Whether GPG should operate in offline mode.";

static PyObject *
pygpgme_context_get_offline(PyGpgmeContext *self)
{
    int offline;

    lock_context(self);
    offline = gpgme_get_offline(self->ctx);
    unlock_context(self);

    return PyBool_FromLong(offline);
}

static int
pygpgme_context_set_offline(PyGpgmeContext *self, PyObject *value)
{
    int offline;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    offline = PyLong_AsLong(value) != 0;
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    gpgme_set_offline(self->ctx, offline);
    unlock_context(self);

    return 0;
}

static const char pygpgme_context_include_certs_doc[] =
    "How many certificates will be included in an S/MIME signed message.\n\n"
    "See GPGME docs for details.";

static PyObject *
pygpgme_context_get_include_certs(PyGpgmeContext *self)
{
    int nr_of_certs;

    lock_context(self);
    nr_of_certs = gpgme_get_include_certs(self->ctx);
    unlock_context(self);

    return PyLong_FromLong(nr_of_certs);
}

static int
pygpgme_context_set_include_certs(PyGpgmeContext *self, PyObject *value)
{
    int nr_of_certs;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    nr_of_certs = PyLong_AsLong(value);
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    gpgme_set_include_certs(self->ctx, nr_of_certs);
    unlock_context(self);

    return 0;
}

static const char pygpgme_context_keylist_mode_doc[] =
    "Default key listing behaviour.\n"
    "\n"
    "Controls which keys :meth:`keylist` returns. The value is a bitwise\n"
    "OR combination of one or multiple of the :class:`KeylistMode`\n"
    "constants. Defaults to :data:`KeylistMode.LOCAL`.";

static PyObject *
pygpgme_context_get_keylist_mode(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_keylist_mode_t mode;

    lock_context(self);
    mode = gpgme_get_keylist_mode(self->ctx);
    unlock_context(self);

    return pygpgme_enum_value_new(state->KeylistMode_Type, mode);
}

static int
pygpgme_context_set_keylist_mode(PyGpgmeContext *self, PyObject *value)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_keylist_mode_t keylist_mode;
    gpgme_error_t err;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    keylist_mode = PyLong_AsLong(value);
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    err = gpgme_set_keylist_mode(self->ctx, keylist_mode);
    unlock_context(self);

    if (pygpgme_check_error(state, err))
        return -1;

    return 0;
}

static const char pygpgme_context_pinentry_mode_doc[] =
    "Set to PINENTRY_MODE_* constant.\n\nSee GPGME docs for details.";

static PyObject *
pygpgme_context_get_pinentry_mode(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_pinentry_mode_t mode;

    lock_context(self);
    mode = gpgme_get_pinentry_mode(self->ctx);
    unlock_context(self);

    return pygpgme_enum_value_new(state->PinentryMode_Type, mode);
}

static int
pygpgme_context_set_pinentry_mode(PyGpgmeContext *self, PyObject *value)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_pinentry_mode_t pinentry_mode;
    gpgme_error_t err;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    pinentry_mode = PyLong_AsLong(value);
    if (PyErr_Occurred())
        return -1;

    lock_context(self);
    err = gpgme_set_pinentry_mode(self->ctx, pinentry_mode);
    unlock_context(self);

    if (pygpgme_check_error(state, err))
        return -1;

    return 0;
}

static const char pygpgme_context_passphrase_cb_doc[] =
    "A callback that will get a passphrase from the user.\n\n"
    "The callable must have the following signature:\n\n"
    "    callback(uidHint, passphraseInfo, prevWasBad, fd)\n\n"
      "uidHint: a string describing the key whose passphrase is needed, or\n"
    "  None.\n\n"
    "passphraseInfo: a string containing more information about the\n"
    "  required passphrase, or None.\n\n"
    "prevWasBad: If the user gave a bad passphrase and we're asking again,\n"
    "  this will be 1, otherwise 0.\n\n"
    "fd: A numeric file-descriptor, as returned by os.open().\n\n"
    "The callback is required to prompt the user for a passphrase, then\n"
    "write the passphrase followed by a '\\n' to the file-descriptor fd\n"
    "using os.write(). If the user indicates they wish to cancel the\n"
    "operation, you should raise a gpgme.GpgmeError whose .code attribute\n"
    "is set to ERR_CANCELED.";

static PyObject *
pygpgme_context_get_passphrase_cb(PyGpgmeContext *self)
{
    gpgme_passphrase_cb_t passphrase_cb;
    PyObject *callback;

    lock_context(self);
    gpgme_get_passphrase_cb(self->ctx, &passphrase_cb, NULL);
    /* Check to make sure it is a Python callback */
    if (passphrase_cb == pygpgme_passphrase_cb) {
        callback = self->passphrase_cb;
    } else {
        callback = Py_None;
    }
    Py_INCREF(callback);
    unlock_context(self);

    return callback;
}

static int
pygpgme_context_set_passphrase_cb(PyGpgmeContext *self, PyObject *value)
{
    /* callback of None == unset */
    if (value == Py_None)
        value = NULL;

    lock_context(self);
    Py_CLEAR(self->passphrase_cb);
    if (value != NULL) {
        Py_INCREF(value);
        self->passphrase_cb = value;
        gpgme_set_passphrase_cb(self->ctx, pygpgme_passphrase_cb, self);
    } else {
        gpgme_set_passphrase_cb(self->ctx, NULL, NULL);
    }
    unlock_context(self);

    return 0;
}

static PyObject *
pygpgme_context_get_progress_cb(PyGpgmeContext *self)
{
    gpgme_progress_cb_t progress_cb;
    PyObject *callback;

    lock_context(self);
    gpgme_get_progress_cb(self->ctx, &progress_cb, NULL);
    /* Check to make sure it is a Python callback */
    if (progress_cb == pygpgme_progress_cb) {
        callback = self->progress_cb;
    } else {
        callback = Py_None;
    }
    Py_INCREF(callback);
    unlock_context(self);

    return callback;
}

static int
pygpgme_context_set_progress_cb(PyGpgmeContext *self, PyObject *value)
{
    /* callback of None == unset */
    if (value == Py_None)
        value = NULL;

    lock_context(self);
    Py_CLEAR(self->progress_cb);
    if (value != NULL) {
        Py_INCREF(value);
        self->progress_cb = value;
        gpgme_set_progress_cb(self->ctx, pygpgme_progress_cb, self);
    } else {
        gpgme_set_progress_cb(self->ctx, NULL, NULL);
    }
    unlock_context(self);

    return 0;
}

static const char pygpgme_context_signers_doc[] =
    "List of :class:`Key` instances used for signing.\n"
    "\n"
    "See also :meth:`sign` and :meth:`encrypt_sign`.";

static PyObject *
pygpgme_context_get_signers(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *list, *tuple = NULL;
    gpgme_key_t key;
    int i;

    lock_context(self);
    list = PyList_New(0);
    for (i = 0, key = gpgme_signers_enum(self->ctx, 0);
         key != NULL; key = gpgme_signers_enum(self->ctx, ++i)) {
        PyObject *item;

        item = pygpgme_key_new(state, key);
        gpgme_key_unref(key);
        if (item == NULL) {
            Py_DECREF(list);
            list = NULL;
            goto end;
        }
        PyList_Append(list, item);
        Py_DECREF(item);
    }

end:
    unlock_context(self);

    if (list != NULL) {
        tuple = PySequence_Tuple(list);
        Py_DECREF(list);
    }
    return tuple;
}

static int
pygpgme_context_set_signers(PyGpgmeContext *self, PyObject *value)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *signers = NULL;
    int i, length, ret = 0;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    signers = PySequence_Fast(value, "signers must be a sequence of keys");
    if (!signers) {
        return -1;
    }

    lock_context(self);
    gpgme_signers_clear(self->ctx);
    length = PySequence_Fast_GET_SIZE(signers);
    for (i = 0; i < length; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(signers, i);

        if (!Py_IS_TYPE(item, state->Key_Type)) {
            PyErr_SetString(PyExc_TypeError,
                            "signers must be a sequence of keys");
            ret = -1;
            goto end;
        }
        gpgme_signers_add(self->ctx, ((PyGpgmeKey *)item)->key);
    }

 end:
    unlock_context(self);
    Py_DECREF(signers);
    return ret;
}

static const char pygpgme_context_sig_notations_doc[] =
    "A tuple of notations added to signatures using the .sign() method.";

static PyObject *
pygpgme_context_get_sig_notations(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *list, *tuple;

    lock_context(self);
    list = pygpgme_sig_notation_list_new(state, gpgme_sig_notation_get(self->ctx));
    unlock_context(self);

    tuple = PySequence_Tuple(list);
    Py_DECREF(list);
    return tuple;
}

static int
pygpgme_context_set_sig_notations(PyGpgmeContext *self, PyObject *value)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *notations = NULL;
    int i, length, ret = -1;
    gpgme_error_t err;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    }

    notations = PySequence_Fast(value, "notations must be a sequence of tuples");
    if (!notations ) {
        return -1;
    }

    lock_context(self);
    gpgme_sig_notation_clear(self->ctx);
    length = PySequence_Fast_GET_SIZE(notations);
    for (i = 0; i < length; i++) {
        PyGpgmeSigNotation *item = (PyGpgmeSigNotation *)PySequence_Fast_GET_ITEM(notations, i);
        const char *name = NULL, *value = NULL;

        if (!Py_IS_TYPE((PyObject *)item, state->SigNotation_Type)) {
            PyErr_SetString(PyExc_TypeError, "sig_notations items must be gpgme.SigNotation objects");
            goto end;
        }

        if (item->name != Py_None) {
            name = PyUnicode_AsUTF8AndSize(item->name, NULL);
        }
        if ((item->flags & GPGME_SIG_NOTATION_HUMAN_READABLE) != 0) {
            value = PyUnicode_AsUTF8AndSize(item->value, NULL);
        } else {
            value = PyBytes_AsString(item->value);
        }

        err = gpgme_sig_notation_add(self->ctx, name, value, item->flags);
        if (pygpgme_check_error(state, err)) {
            goto end;
        }
    }
    ret = 0;

 end:
    unlock_context(self);
    Py_DECREF(notations);
    return ret;
}

static const char pygpgme_context_sender_doc[] =
    "The sender address to include in signatures.";

static PyObject *
pygpgme_context_get_sender(PyGpgmeContext *self)
{
    const char *sender;
    PyObject *py_sender;

    lock_context(self);
    sender = gpgme_get_sender(self->ctx);
    if (sender == NULL) {
        Py_INCREF(Py_None);
        py_sender = Py_None;
    } else {
        py_sender = PyUnicode_FromString(sender);
    }
    unlock_context(self);

    return py_sender;
}

static int
pygpgme_context_set_sender(PyGpgmeContext *self, PyObject *value)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    const char *address;
    gpgme_error_t err;

    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError, "Can not delete attribute");
        return -1;
    } else if (value == Py_None) {
        address = NULL;
    } else if (PyUnicode_Check(value)) {
        address = PyUnicode_AsUTF8AndSize(value, NULL);
    } else {
        PyErr_SetString(PyExc_TypeError, "sender must be a string or None");
        return -1;
    }

    lock_context(self);
    err = gpgme_set_sender(self->ctx, address);
    unlock_context(self);

    return pygpgme_check_error(state, err);
}

static PyGetSetDef pygpgme_context_getsets[] = {
    { "protocol", (getter)pygpgme_context_get_protocol,
      (setter)pygpgme_context_set_protocol,
      pygpgme_context_protocol_doc },
    { "armor", (getter)pygpgme_context_get_armor,
      (setter)pygpgme_context_set_armor,
      pygpgme_context_armor_doc },
    { "textmode", (getter)pygpgme_context_get_textmode,
      (setter)pygpgme_context_set_textmode,
      pygpgme_context_textmode_doc },
    { "offline", (getter)pygpgme_context_get_offline,
      (setter)pygpgme_context_set_offline,
      pygpgme_context_offline_doc },
    { "include_certs", (getter)pygpgme_context_get_include_certs,
      (setter)pygpgme_context_set_include_certs,
      pygpgme_context_include_certs_doc },
    { "keylist_mode", (getter)pygpgme_context_get_keylist_mode,
      (setter)pygpgme_context_set_keylist_mode,
      pygpgme_context_keylist_mode_doc },
    { "pinentry_mode", (getter)pygpgme_context_get_pinentry_mode,
      (setter)pygpgme_context_set_pinentry_mode,
      pygpgme_context_pinentry_mode_doc },
    { "passphrase_cb", (getter)pygpgme_context_get_passphrase_cb,
      (setter)pygpgme_context_set_passphrase_cb,
      pygpgme_context_passphrase_cb_doc },
    { "progress_cb", (getter)pygpgme_context_get_progress_cb,
      (setter)pygpgme_context_set_progress_cb },
    { "signers", (getter)pygpgme_context_get_signers,
      (setter)pygpgme_context_set_signers,
      pygpgme_context_signers_doc },
    { "sig_notations", (getter)pygpgme_context_get_sig_notations,
      (setter)pygpgme_context_set_sig_notations,
      pygpgme_context_sig_notations_doc},
    { "sender", (getter)pygpgme_context_get_sender,
      (setter)pygpgme_context_set_sender,
      pygpgme_context_sender_doc },
    { NULL, (getter)0, (setter)0 }
};

static const char pygpgme_context_set_engine_info_doc[] =
    "set_engine_info($self, protocol, file_name, home_dir, /)\n"
    "--\n\n"
    "Configure a crypto backend.\n"
    "\n"
    "Updates the configuration of the crypto backend for the given protocol.\n"
    "If this function is used then it must be called before any crypto\n"
    "operation is performed on the context.\n"
    "\n"
    "Args:\n"
    "  protocol(Protocol): One of the :class:``Protocol`` constants\n"
    "    specifying which crypto backend is to be configured. Note that\n"
    "    this does not change which crypto backend is actually used, see\n"
    "    :attr:`Context.protocol` for that.\n"
    "  file_name(str): The path to the executable implementing the protocol.\n"
    "    If ``None`` then the default will be used.\n"
    "  home_dir(str): The path of the configuration directory of the crypto\n"
    "    backend. If ``None`` then the default will be used.\n";

static PyObject *
pygpgme_context_set_engine_info(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    int protocol;
    const char *file_name, *home_dir;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "izz", &protocol, &file_name, &home_dir))
        return NULL;

    lock_context(self);
    err = gpgme_ctx_set_engine_info(self->ctx, protocol, file_name, home_dir);
    unlock_context(self);

    if (pygpgme_check_error(state, err))
        return NULL;

    Py_RETURN_NONE;
}

static const char pygpgme_context_get_engine_info_doc[] =
    "get_engine_info($self)\n"
    "--\n\n";

static PyObject *
pygpgme_context_get_engine_info(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_engine_info_t info = gpgme_ctx_get_engine_info(self->ctx);
    PyObject *py_info;

    lock_context(self);
    py_info = pygpgme_engine_info_list_new(state, info);
    unlock_context(self);

    return py_info;
}

static const char pygpgme_context_set_locale_doc[] =
    "set_locale($self, category, value, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_set_locale(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    int category;
    const char *value;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "iz", &category, &value))
        return NULL;

    lock_context(self);
    err = gpgme_set_locale(self->ctx, category, value);
    unlock_context(self);

    if (pygpgme_check_error(state, err))
        return NULL;

    Py_RETURN_NONE;
}

static const char pygpgme_context_get_key_doc[] =
    "get_key($self, fingerprint, secret=False, /)\n"
    "--\n\n"
    "Finds a key with the given fingerprint (a string of hex digits) in\n"
    "the user's keyring.\n"
    "\n"
    "Args:\n"
    "  fingerprint(str): Fingerprint of the key to look for\n"
    "  secret(bool): If True, only private keys will be returned.\n"
    "Returns:\n"
    "  Key: the key matching the fingerprint.\n"
    "\n"
    "If no key can be found, raises :exc:`GpgmeError`.\n";

static PyObject *
pygpgme_context_get_key(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    const char *fpr;
    int secret = 0;
    gpgme_error_t err;
    gpgme_key_t key;
    PyObject *ret;

    if (!PyArg_ParseTuple(args, "s|i", &fpr, &secret))
        return NULL;

    begin_allow_threads(self);
    err = gpgme_get_key(self->ctx, fpr, &key, secret);
    end_allow_threads(self);

    if (pygpgme_check_error(state, err))
        return NULL;

    ret = pygpgme_key_new(state, key);
    gpgme_key_unref(key);
    return ret;
}

/* XXX: cancel -- not needed unless we wrap the async calls */

/* annotate exception with encrypt_result data */
static void
decode_encrypt_result(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *err_type, *err_value, *err_traceback;
    gpgme_encrypt_result_t res;
    gpgme_invalid_key_t key;
    PyObject *list;

    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

    if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
        goto end;

    res = gpgme_op_encrypt_result(self->ctx);
    if (res == NULL)
        goto end;

    list = PyList_New(0);
    for (key = res->invalid_recipients; key != NULL; key = key->next) {
        PyObject *item, *py_fpr, *err;

        if (key->fpr)
            py_fpr = PyUnicode_DecodeASCII(key->fpr, strlen(key->fpr),
                                           "replace");
        else {
            py_fpr = Py_None;
            Py_INCREF(py_fpr);
        }
        err = pygpgme_error_object(state, key->reason);
        item = Py_BuildValue("(NN)", py_fpr, err);
        PyList_Append(list, item);
        Py_DECREF(item);
    }

    PyObject_SetAttrString(err_value, "invalid_recipients", list);
    Py_DECREF(list);

 end:
    PyErr_Restore(err_type, err_value, err_traceback);
}

static const char pygpgme_context_encrypt_doc[] =
    "encrypt($self, recipients, flags, plaintext, ciphertext, /)\n"
    "--\n\n"
    "Encrypts plaintext so it can only be read by the given recipients.\n"
    "\n"
    "Args:\n"
    "  recipients(list[Key]): A list of :class:`Key` objects. Only people in\n"
    "    posession of the corresponding private key (for public key\n"
    "    encryption) or passphrase (for symmetric encryption) will be able\n"
    "    to decrypt the result.\n\n"
    "  flags(EncryptFlags): See GPGME docs for details.\n"
    "  plaintext(file): A file-like object opened for reading, containing\n"
    "    the data to be encrypted.\n"
    "  ciphertext(file): A file-like object opened for writing, where the\n"
    "    encrypted data will be written.\n"
    "\n"
    "See also :meth:`encrypt_sign` and :meth:`decrypt`.\n";

static PyObject *
pygpgme_context_encrypt(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_recp, *py_plain, *py_cipher, *recp_seq = NULL, *result = NULL;
    int flags, i, length;
    gpgme_key_t *recp = NULL;
    gpgme_data_t plain = NULL, cipher = NULL;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "OiOO", &py_recp, &flags,
                          &py_plain, &py_cipher))
        goto end;

    if (py_recp != Py_None) {
        recp_seq = PySequence_Fast(py_recp, "first argument must be a "
                                   "sequence or None");
        if (recp_seq == NULL)
            goto end;

        length = PySequence_Fast_GET_SIZE(recp_seq);
        recp = malloc((length + 1) * sizeof (gpgme_key_t));
        for (i = 0; i < length; i++) {
            PyObject *item = PySequence_Fast_GET_ITEM(recp_seq, i);

            if (!Py_IS_TYPE(item, state->Key_Type)) {
                PyErr_SetString(PyExc_TypeError, "items in first argument "
                                "must be gpgme.Key objects");
                goto end;
            }
            recp[i] = ((PyGpgmeKey *)item)->key;
        }
        recp[i] = NULL;
    }

    if (pygpgme_data_new(state, &plain, py_plain, self))
        goto end;
    if (pygpgme_data_new(state, &cipher, py_cipher, self))
        goto end;

    begin_allow_threads(self);
    err = gpgme_op_encrypt(self->ctx, recp, flags, plain, cipher);
    end_allow_threads(self);

    if (pygpgme_check_error(state, err)) {
        decode_encrypt_result(self);
        goto end;
    }

    Py_INCREF(Py_None);
    result = Py_None;

 end:
    if (recp != NULL)
        free(recp);
    Py_XDECREF(recp_seq);
    gpgme_data_release(plain);
    gpgme_data_release(cipher);

    return result;
}

static const char pygpgme_context_encrypt_sign_doc[] =
    "encrypt_sign($self, recipients, flags, plain, cipher, /)\n"
    "--\n\n"
    "Encrypt and sign plaintext.\n"
    "\n"
    "Works like :meth:`encrypt`, but the ciphertext is also signed using\n"
    "all keys listed in :attr:`Context.signers`.\n"
    "\n"
    "Args:\n"
    "  recipients(list[Key]): A list of :class:`Key` objects. Only people in\n"
    "    posession of the corresponding private key (for public key\n"
    "    encryption) or passphrase (for symmetric encryption) will be able\n"
    "    to decrypt the result.\n\n"
    "  flags(EncryptFlags): See GPGME docs for details.\n"
    "  plaintext(file): A file-like object opened for reading, containing\n"
    "    the data to be encrypted.\n"
    "  ciphertext(file): A file-like object opened for writing, where the\n"
    "    encrypted data will be written.\n"
    "Returns:\n"
    "  list[NewSignature]: A list of :class:`NewSignature` instances (one\n"
    "    for each key in :attr:`Context.signers`).\n"
    "\n"
    "See also :meth:`decrypt_verify`.\n";

static PyObject *
pygpgme_context_encrypt_sign(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_recp, *py_plain, *py_cipher, *recp_seq = NULL, *result = NULL;
    int flags, i, length;
    gpgme_key_t *recp = NULL;
    gpgme_data_t plain = NULL, cipher = NULL;
    gpgme_error_t err;
    gpgme_sign_result_t sign_result;

    if (!PyArg_ParseTuple(args, "OiOO", &py_recp, &flags,
                          &py_plain, &py_cipher))
        goto end;

    recp_seq = PySequence_Fast(py_recp, "first argument must be a sequence");
    if (recp_seq == NULL)
        goto end;

    length = PySequence_Fast_GET_SIZE(recp_seq);
    recp = malloc((length + 1) * sizeof (gpgme_key_t));
    for (i = 0; i < length; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(recp_seq, i);

        if (!Py_IS_TYPE(item, state->Key_Type)) {
            PyErr_SetString(PyExc_TypeError, "items in first argument "
                            "must be gpgme.Key objects");
            goto end;
        }
        recp[i] = ((PyGpgmeKey *)item)->key;
    }
    recp[i] = NULL;

    if (pygpgme_data_new(state, &plain, py_plain, self))
        goto end;
    if (pygpgme_data_new(state, &cipher, py_cipher, self))
        goto end;

    begin_allow_threads(self);
    err = gpgme_op_encrypt_sign(self->ctx, recp, flags, plain, cipher);
    end_allow_threads(self);

    sign_result = gpgme_op_sign_result(self->ctx);

    /* annotate exception */
    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;
        PyObject *list;
        gpgme_invalid_key_t key;

        decode_encrypt_result(self);

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (sign_result == NULL)
            goto error_end;

        if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
            goto error_end;

        list = PyList_New(0);
        for (key = sign_result->invalid_signers; key != NULL; key = key->next) {
            PyObject *item, *py_fpr, *err;

            if (key->fpr)
                py_fpr = PyUnicode_DecodeASCII(key->fpr, strlen(key->fpr),
                                               "replace");
            else {
                py_fpr = Py_None;
                Py_INCREF(py_fpr);
            }
            err = pygpgme_error_object(state, key->reason);
            item = Py_BuildValue("(NN)", py_fpr, err);
            PyList_Append(list, item);
            Py_DECREF(item);
        }
        PyObject_SetAttrString(err_value, "invalid_signers", list);
        Py_DECREF(list);

        list = pygpgme_newsiglist_new(state, sign_result->signatures);
        PyObject_SetAttrString(err_value, "signatures", list);
        Py_DECREF(list);
    error_end:
        PyErr_Restore(err_type, err_value, err_traceback);
        goto end;
    }

    if (sign_result)
        result = pygpgme_newsiglist_new(state, sign_result->signatures);
    else
        result = PyList_New(0);

 end:
    if (recp != NULL)
        free(recp);
    Py_XDECREF(recp_seq);
    gpgme_data_release(plain);
    gpgme_data_release(cipher);

    return result;
}

static void
decode_decrypt_result(PyGpgmeContext *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *err_type, *err_value, *err_traceback;
    PyObject *value;
    gpgme_decrypt_result_t res;

    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

    if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
        goto end;

    res = gpgme_op_decrypt_result(self->ctx);
    if (res == NULL)
        goto end;

    if (res->unsupported_algorithm) {
        value = PyUnicode_DecodeUTF8(res->unsupported_algorithm,
                                     strlen(res->unsupported_algorithm),
                                     "replace");
    } else {
        Py_INCREF(Py_None);
        value = Py_None;
    }
    if (value) {
        PyObject_SetAttrString(err_value, "unsupported_algorithm", value);
        Py_DECREF(value);
    }

    value = PyBool_FromLong(res->wrong_key_usage);
    if (value) {
        PyObject_SetAttrString(err_value, "wrong_key_usage", value);
        Py_DECREF(value);
    }

 end:
    PyErr_Restore(err_type, err_value, err_traceback);
}

static const char pygpgme_context_decrypt_doc[] =
    "decrypt($self, cipher, plain, /)\n"
    "--\n\n"
    "Decrypts the ciphertext and writes out the plaintext.\n"
    "\n"
    "To decrypt data, you must have one of the recipients' private keys in\n"
    "your keyring (for public key encryption) or the passphrase (for\n"
    "symmetric encryption). If gpg finds the key but needs a passphrase to\n"
    "unlock it, the .passphrase_cb callback will be used to ask for it.\n"
    "\n"
    "Args:\n"
    "  cipher(file): A file-like object opened for reading, containing\n"
    "    the encrypted data.\n"
    "  plain(file): A file-like object opened for writing, where the\n"
    "    decrypted data will be written.\n"
    "\n"
    "See also :meth:`decrypt_verify` and :meth:`encrypt`.\n";

static PyObject *
pygpgme_context_decrypt(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_cipher, *py_plain;
    gpgme_data_t cipher, plain;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "OO", &py_cipher, &py_plain))
        return NULL;

    if (pygpgme_data_new(state, &cipher, py_cipher, self)) {
        return NULL;
    }

    if (pygpgme_data_new(state, &plain, py_plain, self)) {
        gpgme_data_release(cipher);
        return NULL;
    }

    begin_allow_threads(self);
    err = gpgme_op_decrypt(self->ctx, cipher, plain);
    end_allow_threads(self);

    gpgme_data_release(cipher);
    gpgme_data_release(plain);

    if (pygpgme_check_error(state, err)) {
        decode_decrypt_result(self);
        return NULL;
    }

    Py_RETURN_NONE;
}

static const char pygpgme_context_decrypt_verify_doc[] =
    "decrypt_verify($self, cipher, plain, /)\n"
    "--\n\n"
    "Decrypt ciphertext and verify signatures.\n"
    "\n"
    "Like :meth:`decrypt`, but also checks the signatures of the ciphertext.\n"
    "\n"
    "Args:\n"
    "  cipher(file): A file-like object opened for reading, containing\n"
    "    the encrypted data.\n"
    "  plain(file): A file-like object opened for writing, where the\n"
    "    decrypted data will be written.\n"
    "Returns:\n"
    "   list[Signature]: A list of :class:`Signature` instances (one for\n"
    "   each key that was used in the signature). Note that you need to\n"
    "   inspect the return value to check whether the signatures are valid\n"
    "   -- a syntactically correct but invalid signature does not raise an\n"
    "   error!\n"
    "\n"
    "See also :py:meth:`encrypt_sign`.";

static PyObject *
pygpgme_context_decrypt_verify(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_cipher, *py_plain;
    gpgme_data_t cipher, plain;
    gpgme_error_t err;
    gpgme_verify_result_t result;

    if (!PyArg_ParseTuple(args, "OO", &py_cipher, &py_plain))
        return NULL;

    if (pygpgme_data_new(state, &cipher, py_cipher, self)) {
        return NULL;
    }

    if (pygpgme_data_new(state, &plain, py_plain, self)) {
        gpgme_data_release(cipher);
        return NULL;
    }

    begin_allow_threads(self);
    err = gpgme_op_decrypt_verify(self->ctx, cipher, plain);
    end_allow_threads(self);

    gpgme_data_release(cipher);
    gpgme_data_release(plain);

    if (pygpgme_check_error(state, err)) {
        decode_decrypt_result(self);
        return NULL;
    }

    result = gpgme_op_verify_result(self->ctx);

    /* annotate exception */
    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;
        PyObject *list;

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (result == NULL)
            goto end;

        if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
            goto end;

        list = pygpgme_siglist_new(state, result->signatures);
        PyObject_SetAttrString(err_value, "signatures", list);
        Py_DECREF(list);
    end:
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }

    if (result)
        return pygpgme_siglist_new(state, result->signatures);
    else
        return PyList_New(0);
}

static const char pygpgme_context_sign_doc[] =
    "sign($self, plain, sig, sig_mode=0, /)\n"
    "--\n\n"
    "Sign plaintext to certify and timestamp it.\n"
    "\n"
    "The plaintext is signed using all keys listed in\n"
    ":attr:`Context.signers`.\n"
    "\n"
    "Args:\n"
    "  plain(file): A file-like object opened for reading, containing the\n"
    "    plaintext to be signed.\n"
    "  sig(file): A file-like object opened for writing, where the signature\n"
    "    data will be written. The signature data may contain the plaintext\n"
    "    or not, see the ``mode`` parameter.\n"
    "  sig_mode(SigMode): One of the :class:``SigMode`` constants.\n"
    "Returns:\n"
    "  list[NewSignature]: A list of :class:`NewSignature` instances (one\n"
    "    for each key in :attr:`Context.signers`).\n";

static PyObject *
pygpgme_context_sign(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_plain, *py_sig;
    gpgme_data_t plain, sig;
    int sig_mode = GPGME_SIG_MODE_NORMAL;
    gpgme_error_t err;
    gpgme_sign_result_t result;

    if (!PyArg_ParseTuple(args, "OO|i", &py_plain, &py_sig, &sig_mode))
        return NULL;

    if (pygpgme_data_new(state, &plain, py_plain, self))
        return NULL;

    if (pygpgme_data_new(state, &sig, py_sig, self)) {
        gpgme_data_release(plain);
        return NULL;
    }

    begin_allow_threads(self);
    err = gpgme_op_sign(self->ctx, plain, sig, sig_mode);
    end_allow_threads(self);

    gpgme_data_release(plain);
    gpgme_data_release(sig);

    result = gpgme_op_sign_result(self->ctx);

    /* annotate exception */
    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;
        PyObject *list;
        gpgme_invalid_key_t key;

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (result == NULL)
            goto end;

        if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
            goto end;

        list = PyList_New(0);
        for (key = result->invalid_signers; key != NULL; key = key->next) {
            PyObject *item, *py_fpr, *err;

            if (key->fpr)
                py_fpr = PyUnicode_DecodeASCII(key->fpr, strlen(key->fpr),
                                               "replace");
            else {
                py_fpr = Py_None;
                Py_INCREF(py_fpr);
            }
            err = pygpgme_error_object(state, key->reason);
            item = Py_BuildValue("(NN)", py_fpr, err);
            PyList_Append(list, item);
            Py_DECREF(item);
        }
        PyObject_SetAttrString(err_value, "invalid_signers", list);
        Py_DECREF(list);

        list = pygpgme_newsiglist_new(state, result->signatures);
        PyObject_SetAttrString(err_value, "signatures", list);
        Py_DECREF(list);
    end:
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }

    if (result)
        return pygpgme_newsiglist_new(state, result->signatures);
    else
        return PyList_New(0);
}

static const char pygpgme_context_verify_doc[] =
    "verify($self, sig, signed_text, plaintext, /)\n"
    "--\n\n"
    "Verify signature(s) and extract plaintext.\n"
    "\n"
    "Args:\n"
    "  sig(file): a file-like object opened for reading, containing the\n"
    "    signature data.\n"
    "  signed_text(file | None): If ``sig`` contains a detached signature\n"
    "    (i.e. created using :data:`SigMode.DETACHED`) then ``signed_text``\n"
    "    should be a file-like object opened for reading containing the text\n"
    "    covered by the signature.\n"
    "  plaintext(file | None): If ``sig`` contains a normal or cleartext\n"
    "    signature (i.e. created using :data:`SigMode.NORMAL` or\n"
    "    :data:`SigMode.CLEAR`) then ``plaintext`` should be a file-like\n"
    "    object opened for writing that will receive the extracted plaintext.\n"
    "Returns:\n"
    "  list[Signature]: A list of :class:`Signature` instances (one for each\n"
    "    key that was used in ``sig``). Note that you need to inspect the\n"
    "    return value to check whether the signatures are valid -- a\n"
    "    syntactically correct but invalid signature does not raise an\n"
    "    error!\n";

static PyObject *
pygpgme_context_verify(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_sig, *py_signed_text, *py_plaintext;
    gpgme_data_t sig, signed_text, plaintext;
    gpgme_error_t err;
    gpgme_verify_result_t result;

    if (!PyArg_ParseTuple(args, "OOO", &py_sig, &py_signed_text,
                          &py_plaintext))
        return NULL;

    if (pygpgme_data_new(state, &sig, py_sig, self)) {
        return NULL;
    }
    if (pygpgme_data_new(state, &signed_text, py_signed_text, self)) {
        gpgme_data_release(sig);
        return NULL;
    }
    if (pygpgme_data_new(state, &plaintext, py_plaintext, self)) {
        gpgme_data_release(sig);
        gpgme_data_release(signed_text);
        return NULL;
    }

    begin_allow_threads(self);
    err = gpgme_op_verify(self->ctx, sig, signed_text, plaintext);
    end_allow_threads(self);

    gpgme_data_release(sig);
    gpgme_data_release(signed_text);
    gpgme_data_release(plaintext);

    result = gpgme_op_verify_result(self->ctx);

    /* annotate exception */
    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;
        PyObject *list;

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (result == NULL)
            goto end;

        if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
            goto end;

        list = pygpgme_siglist_new(state, result->signatures);
        PyObject_SetAttrString(err_value, "signatures", list);
        Py_DECREF(list);
    end:
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }

    if (result)
        return pygpgme_siglist_new(state, result->signatures);
    else
        return PyList_New(0);
}

static const char pygpgme_context_import_doc[] =
    "import_($self, keydata, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_import(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_keydata, *result;
    gpgme_data_t keydata;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "O", &py_keydata))
        return NULL;

    if (pygpgme_data_new(state, &keydata, py_keydata, self))
        return NULL;

    begin_allow_threads(self);
    err = gpgme_op_import(self->ctx, keydata);
    end_allow_threads(self);

    gpgme_data_release(keydata);
    result = pygpgme_import_result(state, self->ctx);
    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
            goto end;

        if (result != NULL) {
            PyObject_SetAttrString(err_value, "result", result);
        }
    end:
        Py_XDECREF(result);
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }
    return result;
}

static const char pygpgme_context_import_keys_doc[] =
    "import_keys($self, keys, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_import_keys(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_keys, *seq = NULL, *result = NULL;
    gpgme_key_t *keys = NULL;
    int i, length;
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (!PyArg_ParseTuple(args, "O", &py_keys))
        return NULL;

    seq = PySequence_Fast(py_keys, "keys must be a sequence of keys");
    if (!seq)
        goto out;

    length = PySequence_Fast_GET_SIZE(seq);
    keys = PyMem_Calloc(length+1, sizeof(gpgme_key_t));
    for (i = 0; i < length; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(seq, i);

        if (!Py_IS_TYPE(item, state->Key_Type)) {
            PyErr_SetString(PyExc_TypeError,
                            "keys must be a sequence of key objects");
            goto out;
        }
        keys[i] = ((PyGpgmeKey *)item)->key;
    }

    begin_allow_threads(self);
    err = gpgme_op_import_keys(self->ctx, keys);
    end_allow_threads(self);

    result = pygpgme_import_result(state, self->ctx);
    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (PyErr_GivenExceptionMatches(err_type, state->pygpgme_error) &&
            result != NULL) {
            PyObject_SetAttrString(err_value, "result", result);
        }
        Py_XDECREF(result);
        result = NULL;
        PyErr_Restore(err_type, err_value, err_traceback);
    }

out:
    PyMem_Free(keys);
    Py_XDECREF(seq);

    return result;
}

static void
free_key_patterns(char **patterns) {
    int i;

    for (i = 0; patterns[i] != NULL; i++) {
        free(patterns[i]);
    }
    free(patterns);
}

/* This function should probably be changed to not accept bytes() when
 * Python 2.x support is dropped. */
static int
parse_key_patterns(PyObject *py_pattern, char ***patterns)
{
    int result = -1, length, i;
    PyObject *list = NULL;

    *patterns = NULL;
    if (py_pattern == Py_None) {
        result = 0;
    } else if (PyUnicode_Check(py_pattern) || PyBytes_Check(py_pattern)) {
        PyObject *bytes;

        if (PyUnicode_Check(py_pattern)) {
            bytes = PyUnicode_AsUTF8String(py_pattern);
            if (bytes == NULL)
                goto end;
        } else {
            bytes = py_pattern;
            Py_INCREF(bytes);
        }
        *patterns = calloc(2, sizeof (char *));
        if (*patterns == NULL) {
            PyErr_NoMemory();
            Py_DECREF(bytes);
            goto end;
        }
        (*patterns)[0] = strdup(PyBytes_AsString(bytes));
        if ((*patterns)[0] == NULL) {
            PyErr_NoMemory();
            Py_DECREF(bytes);
            goto end;
        }
        result = 0;
    } else {
        /* We must have a sequence of strings. */
        list = PySequence_Fast(py_pattern,
            "first argument must be a string or sequence of strings");
        if (list == NULL)
            goto end;

        length = PySequence_Fast_GET_SIZE(list);
        *patterns = calloc((length + 1), sizeof(char *));
        if (*patterns == NULL) {
            PyErr_NoMemory();
            goto end;
        }
        for (i = 0; i < length; i++) {
            PyObject *item = PySequence_Fast_GET_ITEM(list, i);
            PyObject *bytes;

            if (PyBytes_Check(item)) {
                bytes = item;
                Py_INCREF(bytes);
            } else if (PyUnicode_Check(item)) {
                bytes = PyUnicode_AsUTF8String(item);
                if (bytes == NULL) {
                    goto end;
                }
            } else {
                PyErr_SetString(PyExc_TypeError,
                    "first argument must be a string or sequence of strings");
                goto end;
            }
            (*patterns)[i] = strdup(PyBytes_AsString(bytes));
            if ((*patterns)[i] == NULL) {
                PyErr_NoMemory();
                Py_DECREF(bytes);
                goto end;
            }
        }
        result = 0;
    }
 end:
    Py_XDECREF(list);
    /* cleanup the partial pattern list if there was an error*/
    if (result < 0 && *patterns != NULL) {
        free_key_patterns(*patterns);
        *patterns = NULL;
    }
    return result;
}

static const char pygpgme_context_export_doc[] =
    "export($self, pattern, keydata, export_mode=0, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_export(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_pattern, *py_keydata;
    char **patterns = NULL;
    int export_mode = 0;
    gpgme_data_t keydata;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "OO|i", &py_pattern, &py_keydata, &export_mode))
        return NULL;

    if (parse_key_patterns(py_pattern, &patterns) < 0)
        return NULL;

    if (pygpgme_data_new(state, &keydata, py_keydata, self)) {
        if (patterns)
            free_key_patterns(patterns);
        return NULL;
    }

    begin_allow_threads(self);
    err = gpgme_op_export_ext(self->ctx, (const char **)patterns, export_mode, keydata);
    end_allow_threads(self);

    if (patterns)
        free_key_patterns(patterns);
    gpgme_data_release(keydata);
    if (pygpgme_check_error(state, err))
        return NULL;
    Py_RETURN_NONE;
}

static const char pygpgme_context_export_keys_doc[] =
    "export_keys($self, keys, keydata, export_mode=0, /)\n"
    "--\n\n"
    "Export the given list of keys.\n";

static PyObject *
pygpgme_context_export_keys(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_keys, *py_keydata, *seq = NULL, *ret = NULL;
    gpgme_key_t *keys = NULL;
    int i, length, export_mode = 0;
    gpgme_data_t keydata = NULL;
    gpgme_error_t err = GPG_ERR_NO_ERROR;

    if (!PyArg_ParseTuple(args, "OO|i", &py_keys, &py_keydata, &export_mode))
        return NULL;

    seq = PySequence_Fast(py_keys, "keys must be a sequence of keys");
    if (!seq)
        goto out;

    length = PySequence_Fast_GET_SIZE(seq);
    keys = PyMem_Calloc(length+1, sizeof(gpgme_key_t));
    for (i = 0; i < length; i++) {
        PyObject *item = PySequence_Fast_GET_ITEM(seq, i);

        if (!Py_IS_TYPE(item, state->Key_Type)) {
            PyErr_SetString(PyExc_TypeError,
                            "keys must be a sequence of key objects");
            goto out;
        }
        keys[i] = ((PyGpgmeKey *)item)->key;
    }

    if (pygpgme_data_new(state, &keydata, py_keydata, self))
        goto out;

    begin_allow_threads(self);
    err = gpgme_op_export_keys(self->ctx, keys, export_mode, keydata);
    end_allow_threads(self);

    if (pygpgme_check_error(state, err))
        goto out;
    Py_INCREF(Py_None);
    ret = Py_None;

out:
    gpgme_data_release(keydata);
    PyMem_Free(keys);
    Py_XDECREF(seq);

    return ret;
}

static const char pygpgme_context_genkey_doc[] =
    "genkey($self, params, pubkey=None, seckey=None, /)\n"
    "--\n\n"
    "Generate a new key pair.\n"
    "\n"
    "The functionality of this method depends on the crypto backend set\n"
    "via :attr:`Context.protocol`. This documentation only covers PGP/GPG\n"
    "(i.e. :data:`Protocol.OpenPGP`).\n"
    "\n"
    "The generated key pair is automatically added to the key ring. Use\n"
    ":meth:`set_engine_info` to configure the location of the key ring\n"
    "files.\n"
    "\n"
    "Args:\n"
    "  params(str): A string containing the parameters for key generation.\n"
    "    The general syntax is as follows::\n"
    "\n"
    "      <GnupgKeyParms format=\"internal\">\n"
    "        Key-Type: RSA\n"
    "        Key-Length: 2048\n"
    "        Name-Real: Jim Joe\n"
    "        Passphrase: secret passphrase\n"
    "        Expire-Date: 0\n"
    "      </GnupgKeyParms>\n"
    "\n"
    "    For a detailed listing of the available options please refer to the\n"
    "    `GPG key generation documentation`_.\n"
    "  public(file): Must be ``None``.\n"
    "  secret(file): Must be ``None``.\n"
    "Returns:\n"
    "  GenkeyResult: An instance of :class:`gpgme.GenkeyResult`.\n"
    "\n"
    ".. _`GPG key generation documentation`: https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html\n";

static PyObject *
pygpgme_context_genkey(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_pubkey = Py_None, *py_seckey = Py_None;
    const char *parms;
    gpgme_data_t pubkey = NULL, seckey = NULL;
    PyObject *result;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "z|OO", &parms, &py_pubkey, &py_seckey))
        return NULL;

    if (pygpgme_data_new(state, &pubkey, py_pubkey, self))
        return NULL;

    if (pygpgme_data_new(state, &seckey, py_seckey, self)) {
        gpgme_data_release(pubkey);
        return NULL;
    }

    begin_allow_threads(self);
    err = gpgme_op_genkey(self->ctx, parms, pubkey, seckey);
    end_allow_threads(self);

    gpgme_data_release(seckey);
    gpgme_data_release(pubkey);
    result = pygpgme_genkey_result(state, self->ctx);

    if (pygpgme_check_error(state, err)) {
        PyObject *err_type, *err_value, *err_traceback;

        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_NormalizeException(&err_type, &err_value, &err_traceback);

        if (!PyErr_GivenExceptionMatches(err_type, state->pygpgme_error))
            goto end;

        if (result != NULL) {
            PyObject_SetAttrString(err_value, "result", result);
            Py_DECREF(result);
        }
    end:
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }

    return (PyObject *) result;
}

static const char pygpgme_context_delete_doc[] =
    "delete($self, key, flags=0, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_delete(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyGpgmeKey *key;
    unsigned int flags = 0;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "O!|I", state->Key_Type, &key, &flags))
        return NULL;

    begin_allow_threads(self);
    err = gpgme_op_delete_ext(self->ctx, key->key, flags);
    end_allow_threads(self);

    if (pygpgme_check_error(state, err))
        return NULL;
    Py_RETURN_NONE;
}

struct edit_cb_data {
    PyGpgmeContext *self;
    PyObject *callback;
};

static gpgme_error_t
pygpgme_edit_cb(void *user_data, gpgme_status_code_t status,
                const char *args, int fd)
{
    struct edit_cb_data *data = (struct edit_cb_data *)user_data;
    PyGpgmeModState *state;
    PyObject *py_status, *ret;
    gpgme_error_t err;

    assert(data->self->tstate != NULL);
    PyEval_RestoreThread(data->self->tstate);
    state = PyType_GetModuleState(Py_TYPE(data->self));
    py_status = pygpgme_enum_value_new(state->Status_Type, status);
    ret = PyObject_CallFunction(data->callback, "Ozi", py_status, args, fd);
    Py_DECREF(py_status);
    err = pygpgme_check_pyerror(state);
    Py_XDECREF(ret);
    data->self->tstate = PyEval_SaveThread();
    return err;
}

static const char pygpgme_context_edit_doc[] =
    "edit($self, key, callback, out, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_edit(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyGpgmeKey *key;
    PyObject *callback, *py_out;
    gpgme_data_t out;
    struct edit_cb_data data;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "O!OO", state->Key_Type, &key, &callback,
                          &py_out))
        return NULL;

    PyErr_WarnEx(PyExc_DeprecationWarning, "gpgme.Context.edit is deprecated", 1);

    if (pygpgme_data_new(state, &out, py_out, self))
        return NULL;

    begin_allow_threads(self);
    data.self = self;
    data.callback = callback;
    err = gpgme_op_edit(self->ctx, key->key,
                        pygpgme_edit_cb, (void *)&data, out);
    end_allow_threads(self);

    gpgme_data_release(out);

    if (pygpgme_check_error(state, err))
        return NULL;
    Py_RETURN_NONE;
}

static const char pygpgme_context_card_edit_doc[] =
    "card_edit($self, key, callback, out, /)\n"
    "--\n\n";

static PyObject *
pygpgme_context_card_edit(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyGpgmeKey *key;
    PyObject *callback, *py_out;
    gpgme_data_t out;
    struct edit_cb_data data;
    gpgme_error_t err;

    if (!PyArg_ParseTuple(args, "O!OO", state->Key_Type, &key, &callback,
                          &py_out))
        return NULL;

    PyErr_WarnEx(PyExc_DeprecationWarning, "gpgme.Context.card_edit is deprecated", 1);

    if (pygpgme_data_new(state, &out, py_out, self))
        return NULL;

    begin_allow_threads(self);
    data.self = self;
    data.callback = callback;
    err = gpgme_op_card_edit(self->ctx, key->key,
                             pygpgme_edit_cb, (void *)&data, out);
    end_allow_threads(self);

    gpgme_data_release(out);

    if (pygpgme_check_error(state, err))
        return NULL;
    Py_RETURN_NONE;
}

static const char pygpgme_context_keylist_doc[] =
    "keylist($self, pattern=None, secret=False, /)\n"
    "--\n\n"
    "Searches for keys matching the given pattern(s).\n"
    "\n"
    "Args:\n"
    "  pattern(str | list[str] | None): If ``None`` or not supplied, the\n"
    "    :class:`KeyIter` fetches all available keys. If a string, it\n"
    "    fetches keys matching the given pattern (such as a name or email\n"
    "    address). If a sequence of strings, it fetches keys matching at\n"
    "    least one of the given patterns.\n"
    "  secret(bool): If ``True``, only secret keys will be returned (like\n"
    "    'gpg -K').\n"
    "Returns:\n"
    "  KeyIter: an iterator over the matching :class:`Key` objects.\n";

static PyObject *
pygpgme_context_keylist(PyGpgmeContext *self, PyObject *args)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *py_pattern = Py_None;
    char **patterns = NULL;
    int secret_only = 0;
    gpgme_error_t err;
    PyGpgmeKeyIter *ret;

    if (!PyArg_ParseTuple(args, "|Oi", &py_pattern, &secret_only))
        return NULL;

    if (parse_key_patterns(py_pattern, &patterns) < 0)
        return NULL;

    begin_allow_threads(self);
    err = gpgme_op_keylist_ext_start(self->ctx, (const char **)patterns,
                                     secret_only, 0);
    end_allow_threads(self);

    if (patterns)
        free_key_patterns(patterns);

    if (pygpgme_check_error(state, err))
        return NULL;

    /* return a KeyIter object */
    ret = PyObject_New(PyGpgmeKeyIter, state->KeyIter_Type);
    if (!ret)
        return NULL;
    Py_INCREF(self);
    ret->ctx = self;
    return (PyObject *)ret;
}

// pygpgme_context_trustlist

static PyMethodDef pygpgme_context_methods[] = {
    { "get_engine_info", (PyCFunction)pygpgme_context_get_engine_info, METH_VARARGS,
      pygpgme_context_get_engine_info_doc },
    { "set_engine_info", (PyCFunction)pygpgme_context_set_engine_info, METH_VARARGS,
      pygpgme_context_set_engine_info_doc },
    { "set_locale", (PyCFunction)pygpgme_context_set_locale, METH_VARARGS,
      pygpgme_context_set_locale_doc },
    { "get_key", (PyCFunction)pygpgme_context_get_key, METH_VARARGS,
      pygpgme_context_get_key_doc },
    { "encrypt", (PyCFunction)pygpgme_context_encrypt, METH_VARARGS,
      pygpgme_context_encrypt_doc },
    { "encrypt_sign", (PyCFunction)pygpgme_context_encrypt_sign, METH_VARARGS,
      pygpgme_context_encrypt_sign_doc },
    { "decrypt", (PyCFunction)pygpgme_context_decrypt, METH_VARARGS,
      pygpgme_context_decrypt_doc },
    { "decrypt_verify", (PyCFunction)pygpgme_context_decrypt_verify, METH_VARARGS,
      pygpgme_context_decrypt_verify_doc },
    { "sign", (PyCFunction)pygpgme_context_sign, METH_VARARGS,
      pygpgme_context_sign_doc },
    { "verify", (PyCFunction)pygpgme_context_verify, METH_VARARGS,
      pygpgme_context_verify_doc },
    { "import_", (PyCFunction)pygpgme_context_import, METH_VARARGS,
      pygpgme_context_import_doc },
    { "import_keys", (PyCFunction)pygpgme_context_import_keys, METH_VARARGS,
      pygpgme_context_import_keys_doc },
    { "export", (PyCFunction)pygpgme_context_export, METH_VARARGS,
      pygpgme_context_export_doc },
    { "export_keys", (PyCFunction)pygpgme_context_export_keys, METH_VARARGS,
      pygpgme_context_export_keys_doc },
    { "genkey", (PyCFunction)pygpgme_context_genkey, METH_VARARGS,
      pygpgme_context_genkey_doc },
    { "delete", (PyCFunction)pygpgme_context_delete, METH_VARARGS,
      pygpgme_context_delete_doc },
    { "edit", (PyCFunction)pygpgme_context_edit, METH_VARARGS,
      pygpgme_context_edit_doc },
    { "card_edit", (PyCFunction)pygpgme_context_card_edit, METH_VARARGS,
      pygpgme_context_card_edit_doc },
    { "keylist", (PyCFunction)pygpgme_context_keylist, METH_VARARGS,
      pygpgme_context_keylist_doc },
    // trustlist
    { NULL, 0, 0 }
};

static const char pygpgme_context_doc[] =
    "Configuration and internal state for cryptographic operations.\n"
    "\n"
    "This is the main class of :mod:`gpgme`. The constructor takes\n"
    "no arguments::\n"
    "\n"
    "    ctx = gpgme.Context()\n";

static PyType_Slot pygpgme_context_slots[] = {
    { Py_tp_dealloc, pygpgme_context_dealloc },
    { Py_tp_new, pygpgme_context_new },
    { Py_tp_init, pygpgme_context_init },
    { Py_tp_getset, pygpgme_context_getsets },
    { Py_tp_methods, pygpgme_context_methods },
    { Py_tp_doc, (void *)pygpgme_context_doc },
    { 0, NULL },
};

PyType_Spec pygpgme_context_spec = {
    .name = "gpgme.Context",
    .basicsize = sizeof(PyGpgmeContext),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_context_slots,
};
