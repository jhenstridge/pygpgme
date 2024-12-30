/* -*- mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
    pygpgme - a Python wrapper for the gpgme library
    Copyright (C) 2024  James Henstridge

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
#include <structmember.h>

static void
pygpgme_engine_info_dealloc(PyGpgmeEngineInfo *self)
{
    Py_XDECREF(self->protocol);
    Py_XDECREF(self->file_name);
    Py_XDECREF(self->version);
    Py_XDECREF(self->req_version);
    Py_XDECREF(self->home_dir);
}

static PyMemberDef pygpgme_engine_info_members[] = {
    { "protocol", T_OBJECT, offsetof(PyGpgmeEngineInfo, protocol), READONLY},
    { "file_name", T_OBJECT, offsetof(PyGpgmeEngineInfo, file_name), READONLY},
    { "version", T_OBJECT, offsetof(PyGpgmeEngineInfo, version), READONLY},
    { "req_version", T_OBJECT, offsetof(PyGpgmeEngineInfo, req_version), READONLY},
    { "home_dir", T_OBJECT, offsetof(PyGpgmeEngineInfo, home_dir), READONLY},
    { NULL, 0, 0, 0}
};

static PyType_Slot pygpgme_engine_info_slots[] = {
#if PY_VERSION_HEX < 0x030a0000
    { Py_tp_init, pygpgme_no_constructor },
#endif
    { Py_tp_dealloc, pygpgme_engine_info_dealloc },
    { Py_tp_members, pygpgme_engine_info_members },
    { 0, NULL },
};

PyType_Spec pygpgme_engine_info_spec = {
    .name = "gpgme.EngineInfo",
    .basicsize = sizeof(PyGpgmeEngineInfo),
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030a0000
    | Py_TPFLAGS_DISALLOW_INSTANTIATION | Py_TPFLAGS_IMMUTABLETYPE
#endif
    ,
    .slots = pygpgme_engine_info_slots,
};

PyObject *
pygpgme_engine_info_list_new(PyGpgmeModState *state, gpgme_engine_info_t info)
{
    PyObject *list = PyList_New(0);

    for (; info != NULL; info = info->next) {
	PyGpgmeEngineInfo *item = PyObject_New(PyGpgmeEngineInfo,
					       (PyTypeObject *)state->PyGpgmeEngineInfo_Type);
	if (item == NULL) {
	    Py_DECREF(list);
	    return NULL;
	}

	item->protocol = pygpgme_enum_value_new(state->PyGpgmeProtocol_Type, info->protocol);
	if (info->file_name != NULL) {
	    item->file_name = PyUnicode_FromString(info->file_name);
	} else {
	    Py_INCREF(Py_None);
	    item->file_name = Py_None;
	}
	if (info->version != NULL) {
	    item->version = PyUnicode_FromString(info->version);
	} else {
	    Py_INCREF(Py_None);
	    item->version = Py_None;
	}
	if (info->req_version != NULL) {
	    item->req_version = PyUnicode_FromString(info->req_version);
	} else {
	    Py_INCREF(Py_None);
	    item->req_version = Py_None;
	}
	if (info->home_dir != NULL) {
	    item->home_dir = PyUnicode_FromString(info->home_dir);
	} else {
	    Py_INCREF(Py_None);
	    item->home_dir = Py_None;
	}
	PyList_Append(list, (PyObject *)item);
	Py_DECREF(item);
    }
    return list;
}
