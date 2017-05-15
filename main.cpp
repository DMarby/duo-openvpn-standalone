#include "_cgo_export.h"

int countArguments(const char ** const arguments) {
  int count = 0;

  while (arguments[count]) {
    count++;
  }

  return count;
}

int openvpn_plugin_open_v3(const int struct_version,
                       struct openvpn_plugin_args_open_in const *arguments,
                       struct openvpn_plugin_args_open_return *retptr) {
  return InitializePlugin(struct_version, const_cast<struct openvpn_plugin_args_open_in *>(arguments), countArguments(arguments->argv), retptr);
}

int openvpn_plugin_func_v3(const int struct_version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr) {
  return Authenticate(struct_version, const_cast<struct openvpn_plugin_args_func_in *>(arguments), countArguments(arguments->argv), countArguments(arguments->envp), retptr);
}
