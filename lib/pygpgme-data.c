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
#include <assert.h>
#include <errno.h>
#include "pyerrors.h"
#include "pygpgme.h"

struct pygpgme_data {
    PyObject *fp;
    PyGpgmeContext *ctx;
};

/* called when a Python exception is set.  Clears the exception and tries
 * to set errno appropriately. */
static void
set_errno(void)
{
    PyObject *exc, *value, *tb, *py_errno;

    PyErr_Fetch(&exc, &value, &tb);

    /* if we have an IOError, try and get the actual errno */
    if (PyErr_GivenExceptionMatches(exc, PyExc_IOError) && value != NULL) {
        py_errno = PyObject_GetAttrString(value, "errno");
        if (py_errno != NULL && PyLong_Check(py_errno)) {
            errno = PyLong_AsLong(py_errno);
        } else {
            PyErr_Clear();
            errno = EINVAL;
        }
        Py_XDECREF(py_errno);
    } else {
        errno = EINVAL;
    }
    Py_XDECREF(tb);
    Py_XDECREF(value);
    Py_DECREF(exc);
}

static ssize_t
read_cb(void *handle, void *buffer, size_t size)
{
    struct pygpgme_data *data = handle;
    PyObject *result;
    ssize_t result_size;

    assert(data->ctx->tstate != NULL);
    PyEval_RestoreThread(data->ctx->tstate);
    result = PyObject_CallMethod(data->fp, "read", "l", (long)size);
    /* check for exceptions or non-string return values */
    if (result == NULL) {
        set_errno();
        result_size = -1;
        goto end;
    }
    /* if we don't have a string return value, consider that an error too */
    if (!PyBytes_Check(result)) {
        Py_DECREF(result);
        errno = EINVAL;
        result_size = -1;
        goto end;
    }
    /* copy the result into the given buffer */
    result_size = PyBytes_Size(result);
    if ((size_t)result_size > size)
        result_size = size;
    memcpy(buffer, PyBytes_AsString(result), result_size);
    Py_DECREF(result);
 end:
    data->ctx->tstate = PyEval_SaveThread();
    return result_size;
}

static ssize_t
write_cb(void *handle, const void *buffer, size_t size)
{
    struct pygpgme_data *data = handle;
    PyObject *py_buffer = NULL;
    PyObject *result = NULL;
    ssize_t bytes_written = -1;

    assert(data->ctx->tstate != NULL);
    PyEval_RestoreThread(data->ctx->tstate);
    py_buffer = PyBytes_FromStringAndSize(buffer, size);
    if (py_buffer == NULL) {
        set_errno();
        goto end;
    }
    result = PyObject_CallMethod(data->fp, "write", "O", py_buffer);
    if (result == NULL) {
        set_errno();
        goto end;
    }
    bytes_written = size;
 end:
    Py_XDECREF(result);
    Py_XDECREF(py_buffer);
    data->ctx->tstate = PyEval_SaveThread();
    return bytes_written;
}

static off_t
seek_cb(void *handle, off_t offset, int whence)
{
    struct pygpgme_data *data = handle;
    PyObject *result;

    assert(data->ctx->tstate != NULL);
    PyEval_RestoreThread(data->ctx->tstate);
    result = PyObject_CallMethod(data->fp, "seek", "li", (long)offset, whence);
    if (result == NULL) {
        set_errno();
        offset = -1;
        goto end;
    }
    Py_DECREF(result);

    /* now get the file location */
    result = PyObject_CallMethod(data->fp, "tell", NULL);
    if (result == NULL) {
        set_errno();
        offset = -1;
        goto end;
    }
    if (!PyLong_Check(result)) {
        Py_DECREF(result);
        errno = EINVAL;
        offset = -1;
        goto end;
    }
    offset = PyLong_AsLong(result);
    Py_DECREF(result);
 end:
    data->ctx->tstate = PyEval_SaveThread();
    return offset;
}

/* Must hold thread state when releasing */
static void
release_cb(void *handle)
{
    struct pygpgme_data *data = handle;

    Py_DECREF(data->fp);
    Py_DECREF(data->ctx);
    PyMem_Free(data);
}

static struct gpgme_data_cbs python_data_cbs = {
    .read    = read_cb,
    .write   = write_cb,
    .seek    = seek_cb,
    .release = release_cb,
};

/* create a gpgme data object wrapping a Python file like object */
int
pygpgme_data_new(PyGpgmeModState *state, gpgme_data_t *dh, PyObject *fp,
                 PyGpgmeContext *ctx)
{
    gpgme_error_t error;
    struct pygpgme_data *data;

    if (fp == Py_None) {
        *dh = NULL;
        return 0;
    }

    data = PyMem_Malloc(sizeof(struct pygpgme_data));
    if (!data) {
        PyErr_NoMemory();
        return -1;
    }
    data->fp = fp;
    data->ctx = ctx;

    error = gpgme_data_new_from_cbs(dh, &python_data_cbs, data);

    if (pygpgme_check_error(state, error)) {
        *dh = NULL;
        PyMem_Free(data);
        return -1;
    }

    /* if no error, then the new gpgme_data_t object owns a reference to
     * the python object */
    Py_INCREF(fp);
    Py_INCREF(ctx);
    return 0;
}
