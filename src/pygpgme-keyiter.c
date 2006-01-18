/* -*- mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "pygpgme.h"

static void
pygpgme_keyiter_dealloc(PyGpgmeKeyIter *self)
{
    if (self->ctx) {
        gpgme_error_t err = gpgme_op_keylist_end(self->ctx->ctx);
        PyObject *exc = pygpgme_error_object(err);

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

    if (pygpgme_check_error(err))
        return NULL;

    if (key == NULL)
        Py_RETURN_NONE;

    ret = pygpgme_key_new(key);
    gpgme_key_unref(key);
    return ret;
}

PyTypeObject PyGpgmeKeyIter_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "gpgme.KeyIter",
    sizeof(PyGpgmeKeyIter),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_init = pygpgme_no_constructor,
    .tp_dealloc = (destructor)pygpgme_keyiter_dealloc,
    .tp_iter = (getiterfunc)pygpgme_keyiter_iter,
    .tp_iternext = (iternextfunc)pygpgme_keyiter_next,
};
