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

int
pygpgme_no_constructor(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyErr_Format(PyExc_NotImplementedError,
                 "can not directly create instances of %s",
                 self->ob_type->tp_name);
    return -1;
}

static int
pygpgme_mod_exec(PyObject *mod) {
    PyGpgmeModState *state = PyModule_GetState(mod);
    const char *gpgme_version;

    state->pygpgme_error = PyErr_NewException("gpgme.GpgmeError",
                                              PyExc_RuntimeError, NULL);
    Py_INCREF(state->pygpgme_error);
    PyModule_AddObject(mod, "GpgmeError", state->pygpgme_error);

#define INIT_TYPE(type, spec) \
    state->PyGpgme##type##_Type = PyType_FromModuleAndSpec(mod, spec, NULL); \
    if (!state->PyGpgme##type##_Type) \
        return -1; \
    Py_INCREF(state->PyGpgme##type##_Type); \
    PyModule_AddObject(mod, #type, state->PyGpgme##type##_Type)

    INIT_TYPE(Context, &pygpgme_context_spec);
    INIT_TYPE(EngineInfo, &pygpgme_engine_info_spec);
    INIT_TYPE(Key, &pygpgme_key_spec);
    INIT_TYPE(Subkey, &pygpgme_subkey_spec);
    INIT_TYPE(UserId, &pygpgme_user_id_spec);
    INIT_TYPE(KeySig, &pygpgme_key_sig_spec);
    INIT_TYPE(KeyIter, &pygpgme_keyiter_spec);
    INIT_TYPE(NewSignature, &pygpgme_newsig_spec);
    INIT_TYPE(Signature, &pygpgme_sig_spec);
    INIT_TYPE(SigNotation, &pygpgme_sig_notation_spec);
    INIT_TYPE(ImportResult, &pygpgme_import_result_spec);
    INIT_TYPE(GenkeyResult, &pygpgme_genkey_result_spec);

    pygpgme_add_constants(mod);

    gpgme_version = gpgme_check_version(NULL);
    PyModule_AddObject(mod, "gpgme_version",
                       PyUnicode_DecodeASCII(gpgme_version,
                                             strlen(gpgme_version), "replace"));

    return 0;
}

static int
pygpgme_mod_traverse(PyObject *mod, visitproc visit, void *arg)
{
    PyGpgmeModState *state = PyModule_GetState(mod);

    Py_VISIT(state->PyGpgmeContext_Type);
    Py_VISIT(state->PyGpgmeEngineInfo_Type);
    Py_VISIT(state->PyGpgmeKey_Type);
    Py_VISIT(state->PyGpgmeSubkey_Type);
    Py_VISIT(state->PyGpgmeUserId_Type);
    Py_VISIT(state->PyGpgmeKeySig_Type);
    Py_VISIT(state->PyGpgmeKeyIter_Type);
    Py_VISIT(state->PyGpgmeNewSignature_Type);
    Py_VISIT(state->PyGpgmeSignature_Type);
    Py_VISIT(state->PyGpgmeSigNotation_Type);
    Py_VISIT(state->PyGpgmeImportResult_Type);
    Py_VISIT(state->PyGpgmeGenkeyResult_Type);
    Py_VISIT(state->pygpgme_error);
    return 0;
}

static int
pygpgme_mod_clear(PyObject *mod)
{
    PyGpgmeModState *state = PyModule_GetState(mod);

    Py_CLEAR(state->PyGpgmeContext_Type);
    Py_CLEAR(state->PyGpgmeEngineInfo_Type);
    Py_CLEAR(state->PyGpgmeKey_Type);
    Py_CLEAR(state->PyGpgmeSubkey_Type);
    Py_CLEAR(state->PyGpgmeUserId_Type);
    Py_CLEAR(state->PyGpgmeKeySig_Type);
    Py_CLEAR(state->PyGpgmeKeyIter_Type);
    Py_CLEAR(state->PyGpgmeNewSignature_Type);
    Py_CLEAR(state->PyGpgmeSignature_Type);
    Py_CLEAR(state->PyGpgmeSigNotation_Type);
    Py_CLEAR(state->PyGpgmeImportResult_Type);
    Py_CLEAR(state->PyGpgmeGenkeyResult_Type);
    Py_CLEAR(state->pygpgme_error);
    return 0;
}

static void
pygpgme_mod_free(PyObject *mod)
{
    pygpgme_mod_clear(mod);
}

static PyMethodDef pygpgme_mod_functions[] = {
    { NULL, NULL, 0 },
};

static PyModuleDef_Slot pygpgme_mod_slots[] = {
    {Py_mod_exec, pygpgme_mod_exec},
#if PY_VERSION_HEX >= 0x030c0000
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
#endif
    { 0, NULL },
};

static PyModuleDef pygpgme_module = {
    PyModuleDef_HEAD_INIT,
    "gpgme._gpgme",
    .m_size = sizeof (PyGpgmeModState),
    .m_methods = pygpgme_mod_functions,
    .m_slots = pygpgme_mod_slots,
    .m_traverse = (traverseproc)pygpgme_mod_traverse,
    .m_clear = (inquiry)pygpgme_mod_clear,
    .m_free = (freefunc)pygpgme_mod_free,
};

PyMODINIT_FUNC
PyInit__gpgme(void)
{
    const char *gpgme_version;

    gpgme_version = gpgme_check_version("1.13.0");
    if (gpgme_version == NULL) {
        PyErr_SetString(PyExc_ImportError, "Unable to initialize gpgme.");
        return NULL;
    }

    return PyModuleDef_Init(&pygpgme_module);
}
