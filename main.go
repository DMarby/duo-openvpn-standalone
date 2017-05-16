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

	"golang.org/x/crypto/bcrypt"

	"fmt"

	duo "github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"
	"github.com/spf13/cobra"
	viper "github.com/spf13/viper"
	"gopkg.in/yaml.v2"
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
			split := strings.SplitN(item, "=", 2)

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
	var users []user
	err := viper.UnmarshalKey("users", &users)

	if err != nil {
		errorLog(logger, err.Error())
		writeResult(logger, controlFilePath, false)
		return
	}

	user := findUser(users, username)

	if user == nil {
		errorLog(logger, fmt.Sprintf("Unknown user %s", username))
		writeResult(logger, controlFilePath, false)
		return
	}

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

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(parsedPassword)); err != nil {
		errorLog(logger, fmt.Sprintf("Wrong password for user %s", username))
		writeResult(logger, controlFilePath, false)
		return
	}

	duo := createDuoClient()
	err = verifyDuo(duo)

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
		var auth *authapi.AuthResult
		var err error

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

	debugLog(logger, "Authentication attempt")

	if structVersion != C.OPENVPN_PLUGINv3_STRUCTVER {
		errorLog(logger, "Struct version does not match")
		return C.OPENVPN_PLUGIN_FUNC_ERROR
	}

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

	go verifyUser(logger, controlFilePath, username, password, ip)

	return C.OPENVPN_PLUGIN_FUNC_DEFERRED
}

// openvpn_plugin_close_v1 deinitializes the plugin
//export openvpn_plugin_close_v1
func openvpn_plugin_close_v1(handle C.openvpn_plugin_handle_t) {}

// Define main for CLI functionality
func main() {
	var configPath string

	var configCmd = &cobra.Command{
		Use:   "config <integration_key> <secret_key> <api_hostname>",
		Short: "Create or update configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 3 {
				return fmt.Errorf("Invalid arguments")
			}

			err := loadConfig(configPath)

			if err != nil {
				if viper.ConfigFileUsed() != "" {
					configPath = viper.ConfigFileUsed()
				} else {
					configPath = "/etc/duo-openvpn-standalone.yml"
				}
			}

			var tempConfig config
			err = viper.Unmarshal(&tempConfig)

			tempConfig.IntegrationKey = args[0]
			tempConfig.SecretKey = args[1]
			tempConfig.APIHostname = args[2]

			if err != nil {
				return err
			}

			err = saveConfig(configPath, &tempConfig)

			if err != nil {
				return err
			}

			fmt.Printf("Saved config to %s\n", configPath)
			return nil
		},
	}

	var usersCmd = &cobra.Command{
		Use:   "users",
		Short: "List, add and remove users",
	}

	var listCommand = &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := loadConfig(configPath)

			if err != nil {
				return err
			}

			var users []user
			err = viper.UnmarshalKey("users", &users)

			if err != nil {
				return err
			}

			if len(users) == 0 {
				fmt.Printf("There are no users \n")
				return nil
			}

			fmt.Printf("Users: \n")

			for _, user := range users {
				fmt.Printf("%s\n", user.Username)
			}

			return nil
		},
	}

	var addCommand = &cobra.Command{
		Use:   "add <username> <password>",
		Short: "Add a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := loadConfig(configPath)

			if err != nil {
				if viper.ConfigFileUsed() != "" {
					configPath = viper.ConfigFileUsed()
				} else {
					configPath = "/etc/duo-openvpn-standalone.yml"
				}
			}

			var tempConfig config
			err = viper.Unmarshal(&tempConfig)

			if err != nil {
				return err
			}

			for _, user := range tempConfig.Users {
				if user.Username == args[0] {
					return fmt.Errorf("This user already exists!")
				}
			}

			hashedPass, err := bcrypt.GenerateFromPassword([]byte(args[1]), bcrypt.DefaultCost)

			if err != nil {
				return err
			}

			tempConfig.Users = append(tempConfig.Users, user{
				Username: args[0],
				Password: string(hashedPass),
			})

			err = saveConfig(configPath, &tempConfig)

			if err != nil {
				return err
			}

			fmt.Printf("Added user %s to config at %s\n", args[0], configPath)

			return nil
		},
	}

	var removeCommand = &cobra.Command{
		Use:   "remove <username>",
		Short: "Remove a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("Invalid arguments")
			}

			err := loadConfig(configPath)

			if err != nil {
				return err
			}

			if viper.ConfigFileUsed() != "" {
				configPath = viper.ConfigFileUsed()
			} else {
				configPath = "/etc/duo-openvpn-standalone.yml"
			}

			var tempConfig config
			err = viper.Unmarshal(&tempConfig)

			if err != nil {
				return err
			}

			var found = false

			for i, user := range tempConfig.Users {
				if user.Username == args[0] {
					tempConfig.Users = append(tempConfig.Users[:i], tempConfig.Users[i+1:]...)
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("This user does not exist!")
			}

			err = saveConfig(configPath, &tempConfig)

			if err != nil {
				return err
			}

			fmt.Printf("Removed user %s to config at %s\n", args[0], configPath)

			return nil
		},
	}

	var rootCmd = &cobra.Command{Use: "duo-openvpn-standalone"}
	rootCmd.PersistentFlags().StringVarP(&configPath, "config-path", "c", "", "Path to the configuration file")
	rootCmd.AddCommand(configCmd, usersCmd)
	usersCmd.AddCommand(listCommand, addCommand, removeCommand)
	rootCmd.Execute()
}
