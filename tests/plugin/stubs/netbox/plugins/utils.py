SETTINGS = {"netbox_auspex": {"config_path": "/inexistant/auspex.yaml", "internal_subnet": "172.31.250.0/24",
                              "email_backend": "django.core.mail.backends.locmem.EmailBackend",
                              "dashboard_path": "/inexistant/dashboard.json",
                              "carte_url": "https://auspex.test:8443/plugins/auspex/carte-a-puce/"}}


def get_plugin_config(plugin, name):
    return SETTINGS[plugin].get(name)
