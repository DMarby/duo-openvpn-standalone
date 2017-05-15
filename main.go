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
	"os"
	"strings"
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

func createDuoClient() *authapi.AuthApi {
	client := duo.NewDuoApi(
		viper.GetString("integration_key"),
		viper.GetString("secret_key"),
		viper.GetString("api_hostname"),
		"duo-openvpn-standalone",
	)

	return authapi.NewAuthApi(*client)
}

func verifyDuo(duo *authapi.AuthApi) error {
	check, err := duo.Check()

	if err != nil {
		return fmt.Errorf("Invalid duo configuration: %s", err.Error())
	}

	if check.Stat != "OK" {
		return fmt.Errorf("Invalid duo configuration")
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

	argv := readCharArray(arguments.argv, argumentsLength)

	err := loadConfig(argv)

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	err = verifyDuo(createDuoClient())

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	// Tell OpenVPN that we want to listen to OPENVPN_PLUGIN_AUTH_USER_VERIFY
	retptr.type_mask = (1 << (C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY))

	// Create the plugin context containing things we'll need during auth and send it back
	createPluginContext(retptr, logger)

	debugLog(logger, "Initialized")

	return C.OPENVPN_PLUGIN_FUNC_SUCCESS
}

func getEnv(key string, envp []string) string {
	for _, item := range envp {
		if strings.HasPrefix(item, key) && strings.Contains(item, "=") {
			split := strings.Split(item, "=")

			if len(split) > 1 {
				return split[1]
			}
		}
	}

	return ""
}

func writeResult(logger C.plugin_log_t, controlFilePath string, succeeded bool) {
	file, err := os.Create(controlFilePath)

	if err != nil {
		return
	}

	defer file.Close()

	if succeeded {
		file.WriteString("1")
	} else {
		file.WriteString("0")
	}

}

func verifyUser(logger C.plugin_log_t, controlFilePath string, username string, password string, ip string) {
	// TODO: Read username/password from config and verify first
	duo := createDuoClient()
	err := verifyDuo(duo)

	if err != nil {
		errorLog(logger, err.Error())
		writeResult(logger, controlFilePath, false)
		return
	}

	preAuth, err := duo.Preauth(authapi.PreauthUsername(username), authapi.PreauthIpAddr(ip))

	if err != nil {
		errorLog(logger, err.Error())
		writeResult(logger, controlFilePath, false)
		return
	}

	if preAuth.Stat != "OK" {
		errorLog(logger, fmt.Sprintf("Preauth failed for user %s", username))
		writeResult(logger, controlFilePath, false)
		return
	}

	switch preAuth.Response.Result {
	case "allow":
		writeResult(logger, controlFilePath, true)
		return
	case "deny", "enroll":
		writeResult(logger, controlFilePath, false)
		return
	case "auth":
		// TODO: Check if password contains ,<123456> or ,phone or ,push, if so use that (if available) instead
		auth, err := duo.Auth("auto", authapi.AuthUsername(username), authapi.AuthIpAddr(ip), authapi.AuthDevice("auto"))

		if err != nil {
			errorLog(logger, err.Error())
			writeResult(logger, controlFilePath, false)
			return
		}

		if auth.Stat != "OK" {
			errorLog(logger, fmt.Sprintf("Auth failed for user %s: %s, %s", username, *auth.Message, *auth.Message_Detail))
			writeResult(logger, controlFilePath, false)
			return
		}

		if auth.Response.Result == "allow" {
			writeResult(logger, controlFilePath, true)
		} else {
			writeResult(logger, controlFilePath, false)
		}

		return
	}

	writeResult(logger, controlFilePath, false)
}

// Authenticate handles an authentication attempt
//export Authenticate
func Authenticate(structVersion C.int,
	arguments *C.struct_openvpn_plugin_args_func_in,
	argumentsLength C.int,
	envLength C.int,
	retptr *C.struct_openvpn_plugin_args_func_return) C.int {

	// Get the plugin context we passed from the open function
	context := getContext(arguments.handle)
	logger := getLogger(context)

	debugLog(logger, "Authentication attempt")

	if structVersion != C.OPENVPN_PLUGINv3_STRUCTVER {
		errorLog(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	argv := readCharArray(arguments.argv, argumentsLength)

	err := loadConfig(argv)

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	envp := readCharArray(arguments.envp, envLength)

	controlFilePath := getEnv("auth_control_file", envp)
	username := getEnv("username", envp)
	password := getEnv("password", envp)
	ip := getEnv("untrusted_ip", envp)

	if controlFilePath == "" || username == "" || password == "" || ip == "" {
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	go verifyUser(logger, controlFilePath, username, password, ip)

	return C.OPENVPN_PLUGIN_FUNC_DEFERRED
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
