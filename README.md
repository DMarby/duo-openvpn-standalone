# duo-openvpn-standalone
Standalone authentication plugin for openvpn using duo.
This plugin provides the ability to authenticate openvpn users via username/password + duo, without any other external dependencies.

## Installation
Compile the plugin by running `make`. You'll need to have [dep](https://github.com/golang/dep) installed.  
Add the plugin to your openvpn server configuration:
```
plugin /path/to/duo-openvpn-standalone.so
```
By default the plugin will look for the configuration in `/etc/duo-openvpn-standalone.yml`.
If you want to explicitly set a config path, define it after the path to the .so:
```
plugin /path/to/duo-openvpn-standalone.so /path/to/config.yml
```

### Using with daemon mode
If you want to use the plugin when running openvpn in daemon mode, you need to use the intermediary c++ shared library as well.

In order to build it, run `make intermediary`.

This will create a file named `intermediary.so` in the `intermediary` directory.
To use it, add the following to your openvpn server configuration:
```
plugin /path/to/intermediary.so /path/to/duo-openvpn-standalone.so
```
To pass on the config path, simply add it to the end:
```
plugin /path/to/intermediary.so /path/to/duo-openvpn-standalone.so /path/to/config.yml
```

### Configuration
In order to create the configuration, use the CLI tool:
```
./duo-openvpn-standalone config <integration key> <secret key> <api hostname>
```

If you want to provide an explicit configuration path, do so by adding the `"-c"` flag.
```
./duo-openvpn-standalone -c /path/to/config.yml config <integration key> <secret key> <api hostname>
```

To list users:
```
./duo-openvpn-standalone users list
```

To add a user:
```
./duo-openvpn-standalone users add <username> <password>
```

To remove a user:
```
./duo-openpn-standalone users remove <username>
```

## Development
Compile the plugin by running `make`.
Create a configuration file in `docker/duo-openvpn-standalone.yml`, using the CLI tool:
```
./duo-openvpn-standalone -c docker/duo-openvpn-standalone.yml <integration key> <secret key> <api hostname>
```
Add a user to test with:
```
./duo-openvpn-standalone -c docker/duo-openvpn-standalone.yml users add <username> <password>
```
Spin up a local docker container with the plugin loaded:
```
make docker
```
You can connect to it by importing the `docker/client.ovpn` file into your OpenVPN client of choice.

## License
See [LICENSE.md](LICENSE.md)
