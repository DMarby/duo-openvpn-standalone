package main

/*
#include <openvpn-plugin.h>

void call_plugin_log(plugin_log_t plugin_log, openvpn_plugin_log_flags_t log_level, char *message) {
  plugin_log(log_level, "duo-openvpn-standalone", message);
}

typedef struct plugin_context {
  plugin_log_t logger;
} plugin_context;

#cgo CPPFLAGS: -I../lib/openvpn/include
#cgo LDFLAGS: -fPIC
*/
import "C"
import (
	"unsafe"
)

func log(logFunction C.plugin_log_t, logLevel C.openvpn_plugin_log_flags_t, message string) {
	C.call_plugin_log(logFunction, logLevel, C.CString(message))
}

func debugLog(logFunction C.plugin_log_t, message string) {
	log(logFunction, C.PLOG_DEBUG, message)
}

func errorLog(logFunction C.plugin_log_t, message string) {
	log(logFunction, C.PLOG_ERR, message)
}

func createPluginContext(retptr *C.struct_openvpn_plugin_args_open_return, logger C.plugin_log_t) {
	context := new(C.plugin_context)
	context.logger = logger
	retptr.handle = (*C.openvpn_plugin_handle_t)(unsafe.Pointer(context))
}

func getContext(handle C.openvpn_plugin_handle_t) *C.struct_plugin_context {
	return (*C.struct_plugin_context)(handle)
}

func getLogger(context *C.struct_plugin_context) (logger C.plugin_log_t) {
	return context.logger
}

func readCharArray(argv **C.char, length C.int) []string {
	slice := (*[1 << 30]*C.char)(unsafe.Pointer(argv))[:length:length]
	strings := make([]string, length)

	for i, s := range slice {
		strings[i] = C.GoString(s)
	}

	return strings
}
