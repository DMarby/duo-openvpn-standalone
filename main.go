package main

/*
#include <stdlib.h>
#include <openvpn-plugin.h>
#cgo CFLAGS: -Ilib/openvpn/include
#cgo CPPFLAGS: -Ilib/openvpn/include
#cgo LDFLAGS: -fPIC
*/
import "C"

// Declare minimum plugin api version required
//export openvpn_plugin_min_version_required_v1
func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

//export InitializePlugin
func InitializePlugin(struct_version C.int,
	arguments *C.struct_openvpn_plugin_args_open_in,
	retptr *C.struct_openvpn_plugin_args_open_return) C.int {
	return 0
}

// Handle authentication attempt
//export Authenticate
func Authenticate(struct_version C.int,
	arguments *C.struct_openvpn_plugin_args_func_in,
	retptr *C.struct_openvpn_plugin_args_func_return) C.int {
	return 0
}

// Plugin close
//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {

}

// Defined to allow us to create a shared library
func main() {}
