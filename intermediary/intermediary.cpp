#include <openvpn-plugin.h>
#include <stdlib.h>

int openvpn_plugin_select_initialization_point_v1() {
  return OPENVPN_PLUGIN_INIT_POST_DAEMON;
}

int openvpn_plugin_open_v3(const int struct_version,
                       struct openvpn_plugin_args_open_in const *arguments,
                       struct openvpn_plugin_args_open_return *retptr) {
  return 0;
}

int openvpn_plugin_func_v3(const int struct_version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr) {
  return 1;
}
