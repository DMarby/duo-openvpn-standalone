package main

/*
#include <openvpn-plugin.h>
#include <stdlib.h>
#cgo CPPFLAGS: -Ilib/openvpn/include
#cgo LDFLAGS: -fPIC
*/
import "C"

import (
	"unsafe"

	duo "github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"
)

// Declare minimum plugin api version required
//export openvpn_plugin_min_version_required_v1
func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

// Initialize plugin
//export InitializePlugin
func InitializePlugin(struct_version C.int,
	arguments *C.struct_openvpn_plugin_args_open_in,
	retptr *C.struct_openvpn_plugin_args_open_return) C.int {

	// Get function pointer to the openvpn logger
	logger := arguments.callbacks.plugin_log

	if struct_version != C.OPENVPN_PLUGINv3_STRUCTVER {
		error(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	// Tell OpenVPN that we want to listen to OPENVPN_PLUGIN_AUTH_USER_VERIFY
	retptr.type_mask = (1 << (C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY))

	// Create the plugin context containing things we'll need during auth and send it back
	createPluginContext(retptr, logger)

	debug(logger, "Initialized")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

// Handle authentication attempt
//export Authenticate
func Authenticate(struct_version C.int,
	arguments *C.struct_openvpn_plugin_args_func_in,
	retptr *C.struct_openvpn_plugin_args_func_return) C.int {

	// Get the plugin context we passed from the open function
	context := getContext(arguments.handle)
	logger := getLogger(context)

	debug(logger, "Authentication attempt")

	if struct_version != C.OPENVPN_PLUGINv3_STRUCTVER {
		error(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	duoClient := duo.NewDuoApi(
		"ikey",
		"skey",
		"host",
		"",
	)

	d := authapi.NewAuthApi(*duoClient)
	_, _ = d.Check()

	//return C.OPENVPN_PLUGIN_FUNC_DEFERRED
	//return C.OPENVPN_PLUGIN_FUNC_SUCCESS
	return C.OPENVPN_PLUGIN_FUNC_ERROR
}

// Deinitialize plugin
//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {
	// TODO: Test this
	context := getContext(handle)
	C.free(unsafe.Pointer(context))
}

// Define main to allow us to create a shared library
func main() {}
