#include "_cgo_export.h"
#include <type_traits>
#include <cstring>

int openvpn_plugin_open_v3(const int struct_version,
                       struct openvpn_plugin_args_open_in const *arguments,
                       struct openvpn_plugin_args_open_return *retptr) {
  int argc = 0;

  while (arguments->argv[argc]) {
    argc++;
  }

  return InitializePlugin(struct_version, const_cast<struct openvpn_plugin_args_open_in *>(arguments), argc, retptr);
}

int openvpn_plugin_func_v3(const int struct_version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr) {
  return Authenticate(struct_version, const_cast<struct openvpn_plugin_args_func_in *>(arguments), retptr);
}
