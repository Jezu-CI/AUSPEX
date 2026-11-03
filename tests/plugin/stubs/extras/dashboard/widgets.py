"""Doublure du cadre de widgets du tableau de bord de NetBox 4."""
from django import forms

REGISTRY = {}


class WidgetConfigForm(forms.Form):
    pass


class DashboardWidget:
    default_title = None
    description = None
    width = 4
    height = 3

    class ConfigForm(WidgetConfigForm):
        pass

    def __init__(self, id=None, title=None, color=None, config=None, width=None, height=None, x=None, y=None):
        self.config = config or {}
        self.title = title or self.default_title


def register_widget(cls):
    REGISTRY[f"{cls.__module__.split('.', 1)[0]}.{cls.__name__}"] = cls
    return cls
