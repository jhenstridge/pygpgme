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
pygpgme_keyiter_dealloc(PyGpgmeKeyIter *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));

    if (self->ctx) {
        gpgme_error_t err = gpgme_op_keylist_end(self->ctx->ctx);
        PyObject *exc = pygpgme_error_object(state, err);

        if (exc != NULL && exc != Py_None) {
            PyErr_WriteUnraisable(exc);
        }
        Py_XDECREF(exc);
        Py_DECREF(self->ctx);
        self->ctx = NULL;
    }
    PyObject_Del(self);
}

static PyObject *
pygpgme_keyiter_iter(PyGpgmeKeyIter *self)
{
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *
pygpgme_keyiter_next(PyGpgmeKeyIter *self)
{
    PyGpgmeModState *state = PyType_GetModuleState(Py_TYPE(self));
    gpgme_key_t key = NULL;
    gpgme_error_t err;
    PyObject *ret;

    Py_BEGIN_ALLOW_THREADS;
    err = gpgme_op_keylist_next(self->ctx->ctx, &key);
    Py_END_ALLOW_THREADS;

    /* end iteration */
    if (gpgme_err_source(err) == GPG_ERR_SOURCE_GPGME &&
        gpgme_err_code(err) == GPG_ERR_EOF) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    if (pygpgme_check_error(state, err))
        return NULL;

    if (key == NULL)
        Py_RETURN_NONE;

    ret = pygpgme_key_new(state, key);
    gpgme_key_unref(key);
    return ret;
}

static PyType_Slot pygpgme_keyiter_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_keyiter_dealloc },
    { Py_tp_iter, pygpgme_keyiter_iter },
    { Py_tp_iternext, pygpgme_keyiter_next },
    { 0, NULL },
};

PyType_Spec pygpgme_keyiter_spec = {
    .name = "gpgme.KeyIter",
    .basicsize = sizeof(PyGpgmeKeyIter),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_keyiter_slots,
};
