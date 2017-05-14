#include "_cgo_export.h"

int openvpn_plugin_open_v3(const int struct_version,
                       struct openvpn_plugin_args_open_in const *arguments,
                       struct openvpn_plugin_args_open_return *retptr) {

  return InitializePlugin(struct_version, const_cast<struct openvpn_plugin_args_open_in *>(arguments), retptr);
}

int openvpn_plugin_func_v3(const int struct_version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr) {
  return Authenticate(struct_version, const_cast<struct openvpn_plugin_args_func_in *>(arguments), retptr);
}
