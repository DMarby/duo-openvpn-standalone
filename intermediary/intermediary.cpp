#include <openvpn-plugin.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int (*open)(const int struct_version,
    struct openvpn_plugin_args_open_in const *arguments,
    struct openvpn_plugin_args_open_return *retptr);

typedef int (*func)(const int struct_version,
    struct openvpn_plugin_args_func_in const *arguments,
    struct openvpn_plugin_args_func_return *retptr);

typedef void (*close)(openvpn_plugin_handle_t handle);

struct plugin {
  void *handle;

  open p_open;
  func p_func;
  close p_close;
};

plugin p = plugin();

int openvpn_plugin_min_version_required_v1() {
	return 3;
}

int openvpn_plugin_select_initialization_point_v1() {
  return OPENVPN_PLUGIN_INIT_POST_DAEMON;
}

int openvpn_plugin_open_v3(const int struct_version,
                       struct openvpn_plugin_args_open_in const *arguments,
                       struct openvpn_plugin_args_open_return *retptr) {
  if (!arguments->argv[1]) {
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  p.handle = dlopen(arguments->argv[1], RTLD_NOW);

  if (!p.handle) {
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  p.p_open = (open) dlsym(p.handle, "openvpn_plugin_open_v3");

  if (!p.p_open) {
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  p.p_func = (func) dlsym(p.handle, "openvpn_plugin_func_v3");

  if (!p.p_func) {
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  p.p_close = (close) dlsym(p.handle, "openvpn_plugin_close_v1");

  if (!p.p_close) {
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  const char** const new_argv = arguments->argv + 1;

  const openvpn_plugin_args_open_in new_arguments = {
    arguments->type_mask,
    new_argv,
    arguments->envp,
    arguments->callbacks,
    arguments->ssl_api
  };

  return p.p_open(struct_version, &new_arguments, retptr);
}

int openvpn_plugin_func_v3(const int struct_version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr) {
  const char** const new_argv = arguments->argv + 1;

  const openvpn_plugin_args_func_in new_arguments = {
    arguments->type,
    arguments->argv,
    arguments->envp,
    arguments->handle,
    arguments->per_client_context
  };

  return p.p_func(struct_version, &new_arguments, retptr);
}

void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle) {
  p.p_close(handle);
  dlclose(p.handle);
}
