"""Doublure minimale de netbox.plugins pour tester le plugin sans NetBox."""
from django.apps import AppConfig


class PluginConfig(AppConfig):
    pass


class PluginMenuItem:
    def __init__(self, link, link_text, permissions=None, buttons=(), **kw):
        self.link, self.link_text, self.permissions, self.buttons = link, link_text, permissions or [], buttons
