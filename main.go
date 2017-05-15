package main

/*
#include <openvpn-plugin.h>
#include <stdlib.h>
#cgo CPPFLAGS: -Ilib/openvpn/include
#cgo CXXFLAGS: -std=c++11
#cgo LDFLAGS: -fPIC
*/
import "C"

import (
	"unsafe"

	"fmt"

	duo "github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"
	viper "github.com/spf13/viper"
)

// openvpn_plugin_min_version_required_v1 declares the minimum plugin api version required
//export openvpn_plugin_min_version_required_v1
func openvpn_plugin_min_version_required_v1() C.int {
	return 3
}

var requiredConfigurationKeys = []string{
	"integration_key",
	"secret_key",
	"api_hostname",
	"users",
}

func loadConfig(argv []string) error {
	if len(argv) > 1 { // If we get an argument from OpenVPN, explicitly set the config file to that
		viper.SetConfigFile(argv[1])
	} else { // Otherwise read the config from the work directory, or /etc/duo-openvpn-standalone.yml
		viper.SetConfigName("duo-openvpn-standalone")
		viper.AddConfigPath("/etc/")
		viper.AddConfigPath(".")
	}

	err := viper.ReadInConfig()

	if err != nil {
		return fmt.Errorf("Error loading configuration %s", err.Error())
	}

	err = validateConfig()

	if err != nil {
		return fmt.Errorf("Error validating configuration %s", err.Error())
	}

	return nil
}

func validateConfig() error {
	for _, key := range requiredConfigurationKeys {
		if !viper.IsSet(key) {
			return fmt.Errorf("Missing configuration key: %s", key)
		}
	}

	return nil
}

// InitializePlugin initializes the plugin
//export InitializePlugin
func InitializePlugin(structVersion C.int,
	arguments *C.struct_openvpn_plugin_args_open_in,
	argumentsLength C.int,
	retptr *C.struct_openvpn_plugin_args_open_return) C.int {

	// Get function pointer to the openvpn logger
	logger := arguments.callbacks.plugin_log

	if structVersion != C.OPENVPN_PLUGINv3_STRUCTVER {
		errorLog(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	argv := getArguments(arguments.argv, argumentsLength)

	err := loadConfig(logger)

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_ERROR
	}

	// Tell OpenVPN that we want to listen to OPENVPN_PLUGIN_AUTH_USER_VERIFY
	retptr.type_mask = (1 << (C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY))

	// Create the plugin context containing things we'll need during auth and send it back
	createPluginContext(retptr, logger)

	debugLog(logger, "Initialized")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

// Authenticate handles an authentication attempt
//export Authenticate
func Authenticate(structVersion C.int,
	arguments *C.struct_openvpn_plugin_args_func_in,
	retptr *C.struct_openvpn_plugin_args_func_return) C.int {

	// Get the plugin context we passed from the open function
	context := getContext(arguments.handle)
	logger := getLogger(context)

	debugLog(logger, "Authentication attempt")

	if structVersion != C.OPENVPN_PLUGINv3_STRUCTVER {
		errorLog(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	err := loadConfig(logger)

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	duoClient := duo.NewDuoApi(
		viper.GetString("integration_key"),
		viper.GetString("secret_key"),
		viper.GetString("api_hostname"),
		"duo-openvpn-standalone",
	)

	d := authapi.NewAuthApi(*duoClient)
	_, _ = d.Check()

	//return C.OPENVPN_PLUGIN_FUNC_DEFERRED
	//return C.OPENVPN_PLUGIN_FUNC_SUCCESS
	return C.OPENVPN_PLUGIN_FUNC_ERROR
}

// openvpn_plugin_close_v1 deinitializes the plugin
//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {
	// TODO: Test this
	context := getContext(handle)
	C.free(unsafe.Pointer(context))
}

// Define main to allow us to create a shared library
func main() {}
