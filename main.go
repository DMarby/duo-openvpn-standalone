package main

/*
#cgo CFLAGS: -Ilib/openvpn/include
#cgo LDFLAGS: -fPIC -I.
#include <openvpn-plugin.h>
*/
import "C"

// Declare minimum plugin api version required
//export openvpn_plugin_min_version_required_v1
func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

// Plugin initialization
//export openvpn_plugin_open_v3
func openvpn_plugin_open_v3(struct_version C.int,
	arguments *C.openvpn_plugin_args_open_in,
	retptr *C.openvpn_plugin_args_open_return) C.int {

}

// Handle authentication attempt
//export openvpn_plugin_func_v3
func openvpn_plugin_func_v3(struct_version C.int,
	arguments *C.openvpn_plugin_args_func_in,
	retptr *C.openvpn_plugin_args_func_return) C.int {
}

// Plugin close
//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {

}

// Defined to allow us to create a shared library
func main() {}
