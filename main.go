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
	"regexp"
	"strings"
	"unsafe"

	"golang.org/x/crypto/bcrypt"

	"fmt"

	duo "github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"
	viper "github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var requiredConfigurationKeys = []string{
	"integration_key",
	"secret_key",
	"api_hostname",
}

func loadConfig(configPath string) error {
	if configPath != "" { // If we got an explicit configPath, set config to that
		viper.SetConfigFile(configPath)
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

func saveConfig(configPath string, tempConfig *config) error {
	bytes, err := yaml.Marshal(tempConfig)
	if err != nil {
		return err
	}

	file, err := os.Create(configPath)
	if err != nil {
		return err
	}

	defer file.Close()

	file.Write(bytes)

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

	debugLog(logger, "Initializing")

	argv := readCharArray(arguments.argv, argumentsLength)

	var configPath = ""

	if len(argv) > 1 {
		configPath = argv[1] // If we get an argument from OpenVPN, explicitly set the config file to that
	}

	debugLog(logger, "Loading configuration")

	err := loadConfig(configPath)

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	debugLog(logger, "Verifying duo")

	err = verifyDuo(createDuoClient())

	if err != nil {
		errorLog(logger, err.Error())
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	debugLog(logger, "Creating plugin context")

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
			split := strings.SplitN(item, "=", 2)

			if len(split) > 1 {
				return split[1]
			}
		}
	}

	return ""
}

func writeResult(logger C.plugin_log_t, controlFilePath string, succeeded bool) {
	debugLog(logger, fmt.Sprintf("Writing result %t", succeeded))

	file, err := os.Create(controlFilePath)

	if err != nil {
		errorLog(logger, fmt.Sprintf("Error writing result %s", err.Error()))
		return
	}

	defer file.Close()

	if succeeded {
		file.WriteString("1")
	} else {
		file.WriteString("0")
	}

}

type user struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type config struct {
	IntegrationKey string `mapstructure:"integration_key" yaml:"integration_key"`
	SecretKey      string `mapstructure:"secret_key" yaml:"secret_key"`
	APIHostname    string `mapstructure:"api_hostname" yaml:"api_hostname"`
	Users          []user `yaml:"users,omitempty"`
}

func findUser(users []user, username string) *user {
	for _, user := range users {
		if user.Username == username {
			return &user
		}
	}

	return nil
}

func verifyUser(logger C.plugin_log_t, controlFilePath string, username string, password string, ip string) {
	debugLog(logger, "Loading users")

	var users []user
	err := viper.UnmarshalKey("users", &users)

	if err != nil {
		errorLog(logger, err.Error())
		writeResult(logger, controlFilePath, false)
		return
	}

	debugLog(logger, "Finding user")

	user := findUser(users, username)

	if user == nil {
		errorLog(logger, fmt.Sprintf("Unknown user %s", username))
		writeResult(logger, controlFilePath, false)
		return
	}

	debugLog(logger, "Parsing password")

	var parsedPassword = password
	var authMethod = "auto"

	passRegex := regexp.MustCompile("(^.*),([0-9]{6,7}|push|phone|sms)$")

	if passRegex.MatchString(password) {
		passRegexMatch := passRegex.FindStringSubmatch(password)

		if len(passRegexMatch) > 2 {
			parsedPassword = passRegexMatch[1]
			authMethod = passRegexMatch[2]
		}
	}

	debugLog(logger, "Comparing password to hash")

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(parsedPassword)); err != nil {
		errorLog(logger, fmt.Sprintf("Wrong password for user %s", username))
		writeResult(logger, controlFilePath, false)
		return
	}

	debugLog(logger, "Creating duo client")

	duo := createDuoClient()

	debugLog(logger, "Verifying duo")

	err = verifyDuo(duo)

	if err != nil {
		errorLog(logger, err.Error())
		writeResult(logger, controlFilePath, false)
		return
	}

	debugLog(logger, "Running duo preauth")

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

	debugLog(logger, "Handling duo preauth response")

	switch preAuth.Response.Result {
	case "allow":
		writeResult(logger, controlFilePath, true)
		return
	case "deny", "enroll":
		writeResult(logger, controlFilePath, false)
		return
	case "auth":
		var auth *authapi.AuthResult
		var err error

		debugLog(logger, "Running duo auth")

		if authMethod != "auto" && authMethod != "push" && authMethod != "phone" && authMethod != "sms" {
			auth, err = duo.Auth("passcode", authapi.AuthUsername(username), authapi.AuthIpAddr(ip), authapi.AuthPasscode(authMethod))
		} else {
			auth, err = duo.Auth(authMethod, authapi.AuthUsername(username), authapi.AuthIpAddr(ip), authapi.AuthDevice("auto"))
		}

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
	default:
		errorLog(logger, fmt.Sprintf("Unknown preauth response %s", preAuth.Response.Result))
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

	// Get the plugin context we passed from the InitializePlugin function
	context := getContext(arguments.handle)
	logger := getLogger(context)

	if structVersion != C.OPENVPN_PLUGINv3_STRUCTVER {
		errorLog(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

	debugLog(logger, "Authentication attempt")

	argv := readCharArray(arguments.argv, argumentsLength)

	var configPath = ""

	if len(argv) > 1 {
		configPath = argv[1] // If we get an argument from OpenVPN, explicitly set the config file to that
	}

	err := loadConfig(configPath)

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

	debugLog(logger, fmt.Sprintf("Deferring authentication for user %s (%s), path %s", username, ip, controlFilePath))

	go verifyUser(logger, controlFilePath, username, password, ip)

	return C.OPENVPN_PLUGIN_FUNC_DEFERRED
}

// openvpn_plugin_close_v1 deinitializes the plugin
//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {
	context := getContext(handle)
	C.free(unsafe.Pointer(context))
}

// Define main for CLI functionality
func main() {
	initializeCommands()
}
