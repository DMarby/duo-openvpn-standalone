package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

func initializeCommands() {
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
			if len(args) != 2 {
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
