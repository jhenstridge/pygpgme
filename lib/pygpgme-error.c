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

PyObject *
pygpgme_error_object(PyGpgmeModState *state, gpgme_error_t err)
{
    char buf[256] = { '\0' };
    PyObject *exc = NULL, *source = NULL, *code = NULL, *strerror = NULL;

    if (err == GPG_ERR_NO_ERROR)
        Py_RETURN_NONE;

    if (!(source = pygpgme_enum_value_new(PyGpgmeErrSource_Type, gpgme_err_source(err))))
        goto end;

    if (!(code = pygpgme_enum_value_new(PyGpgmeErrCode_Type, gpgme_err_code(err))))
        goto end;

    /* get the error string */
    if (gpgme_strerror_r(err, buf, sizeof(buf) - 1) != 0)
        strcpy(buf, "Unknown");
    if (!(strerror = PyUnicode_DecodeUTF8(buf, strlen(buf), "replace")))
        goto end;

    exc = PyObject_CallFunction(state->pygpgme_error, "OOO", source, code, strerror);
    if (!exc)
        goto end;

    /* set the source and code as attributes of the exception object: */
    PyObject_SetAttrString(exc, "source", source);
    PyObject_SetAttrString(exc, "code", code);
    PyObject_SetAttrString(exc, "strerror", strerror);

end:
    Py_XDECREF(strerror);
    Py_XDECREF(code);
    Py_XDECREF(source);
    return exc;
}

/* check whether the given gpgme_error_t value indicates an error.  If so,
 * raise an equivalent Python exception and return TRUE */
int
pygpgme_check_error(PyGpgmeModState *state, gpgme_error_t err)
{
    PyObject *exc;

    if (err == GPG_ERR_NO_ERROR)
        return 0;

    exc = pygpgme_error_object(state, err);
    if (!exc)
        return -1;

    PyErr_SetObject(state->pygpgme_error, exc);

    return -1;
}

gpgme_error_t
pygpgme_check_pyerror(PyGpgmeModState *state)
{
    PyObject *err_type, *err_value, *err_traceback;
    gpgme_error_t err;
    PyObject *args = NULL, *source = NULL, *code = NULL;

    if (!PyErr_Occurred())
        return GPG_ERR_NO_ERROR;

    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    PyErr_NormalizeException(&err_type, &err_value, &err_traceback);
    err = gpgme_error(GPG_ERR_GENERAL);

    /* get the first argument of the exception */
    args = PyObject_GetAttrString(err_value, "args");
    if (args == NULL)
        goto end;

    source = PyTuple_GetItem(args, 0);
    if (source == NULL)
        goto end;

    if (PyErr_GivenExceptionMatches(err_type, state->pygpgme_error)) {
        code = PyTuple_GetItem(args, 1);
        if (code == NULL)
            goto end;

        if (PyLong_Check(source) && PyLong_Check(code))
            err = gpgme_err_make(PyLong_AsLong(source), PyLong_AsLong(code));
    } else if (PyErr_GivenExceptionMatches(err_type, PyExc_IOError) ||
               PyErr_GivenExceptionMatches(err_type, PyExc_OSError)) {
        if (PyLong_Check(source))
            err = gpgme_err_code_from_errno(PyLong_AsLong(source));
    }

 end:
    Py_XDECREF(err_type);
    Py_XDECREF(err_value);
    Py_XDECREF(err_traceback);
    Py_XDECREF(args);
    PyErr_Clear();

    return err;
}
