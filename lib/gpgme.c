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
    state->type##_Type = (PyTypeObject *)PyType_FromModuleAndSpec(mod, spec, NULL); \
    if (!state->type##_Type) \
        return -1; \
    Py_INCREF(state->type##_Type); \
    PyModule_AddObject(mod, #type, (PyObject *)state->type##_Type)

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

    Py_VISIT(state->Context_Type);
    Py_VISIT(state->EngineInfo_Type);
    Py_VISIT(state->Key_Type);
    Py_VISIT(state->Subkey_Type);
    Py_VISIT(state->UserId_Type);
    Py_VISIT(state->KeySig_Type);
    Py_VISIT(state->KeyIter_Type);
    Py_VISIT(state->NewSignature_Type);
    Py_VISIT(state->Signature_Type);
    Py_VISIT(state->SigNotation_Type);
    Py_VISIT(state->ImportResult_Type);
    Py_VISIT(state->GenkeyResult_Type);

    Py_VISIT(state->DataEncoding_Type);
    Py_VISIT(state->PubkeyAlgo_Type);
    Py_VISIT(state->HashAlgo_Type);
    Py_VISIT(state->SigMode_Type);
    Py_VISIT(state->Validity_Type);
    Py_VISIT(state->Protocol_Type);
    Py_VISIT(state->KeylistMode_Type);
    Py_VISIT(state->PinentryMode_Type);
    Py_VISIT(state->ExportMode_Type);
    Py_VISIT(state->SigNotationFlags_Type);
    Py_VISIT(state->Status_Type);
    Py_VISIT(state->EncryptFlags_Type);
    Py_VISIT(state->Sigsum_Type);
    Py_VISIT(state->Import_Type);
    Py_VISIT(state->Delete_Type);
    Py_VISIT(state->ErrSource_Type);
    Py_VISIT(state->ErrCode_Type);

    Py_VISIT(state->pygpgme_error);
    return 0;
}

static int
pygpgme_mod_clear(PyObject *mod)
{
    PyGpgmeModState *state = PyModule_GetState(mod);

    Py_CLEAR(state->Context_Type);
    Py_CLEAR(state->EngineInfo_Type);
    Py_CLEAR(state->Key_Type);
    Py_CLEAR(state->Subkey_Type);
    Py_CLEAR(state->UserId_Type);
    Py_CLEAR(state->KeySig_Type);
    Py_CLEAR(state->KeyIter_Type);
    Py_CLEAR(state->NewSignature_Type);
    Py_CLEAR(state->Signature_Type);
    Py_CLEAR(state->SigNotation_Type);
    Py_CLEAR(state->ImportResult_Type);
    Py_CLEAR(state->GenkeyResult_Type);

    Py_CLEAR(state->DataEncoding_Type);
    Py_CLEAR(state->PubkeyAlgo_Type);
    Py_CLEAR(state->HashAlgo_Type);
    Py_CLEAR(state->SigMode_Type);
    Py_CLEAR(state->Validity_Type);
    Py_CLEAR(state->Protocol_Type);
    Py_CLEAR(state->KeylistMode_Type);
    Py_CLEAR(state->PinentryMode_Type);
    Py_CLEAR(state->ExportMode_Type);
    Py_CLEAR(state->SigNotationFlags_Type);
    Py_CLEAR(state->Status_Type);
    Py_CLEAR(state->EncryptFlags_Type);
    Py_CLEAR(state->Sigsum_Type);
    Py_CLEAR(state->Import_Type);
    Py_CLEAR(state->Delete_Type);
    Py_CLEAR(state->ErrSource_Type);
    Py_CLEAR(state->ErrCode_Type);

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
    { Py_mod_exec, pygpgme_mod_exec },
#if PY_VERSION_HEX >= 0x030c0000
    { Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED },
#endif
#if PY_VERSION_HEX >= 0x030d0000
    { Py_mod_gil, Py_MOD_GIL_NOT_USED },
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
