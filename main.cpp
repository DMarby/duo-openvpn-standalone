#include "_cgo_export.h"

struct plugin_context {};

int openvpn_plugin_open_v3(const int struct_version,
                       struct openvpn_plugin_args_open_in const *arguments,
                       struct openvpn_plugin_args_open_return *retptr) {

  // Tell OpenVPN that we want to listen to OPENVPN_PLUGIN_AUTH_USER_VERIFY
  retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

  struct plugin_context *context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));

  // Pass OpenVPN a handle to the context, it'll return this in the plugin_func call
  retptr->handle = (openvpn_plugin_handle_t*) context;

  return InitializePlugin(struct_version, const_cast<struct openvpn_plugin_args_open_in *>(arguments), retptr);
}

int openvpn_plugin_func_v3(const int struct_version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr) {
  return Authenticate(struct_version, const_cast<struct openvpn_plugin_args_func_in *>(arguments), retptr);
}
