from netbox.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(link="plugins:netbox_auspex:map", link_text="Carte des actifs",
                   permissions=["ipam.view_ipaddress"]),
    PluginMenuItem(link="plugins:netbox_auspex:findings", link_text="Écarts de conformité",
                   permissions=["ipam.view_ipaddress"]),
    PluginMenuItem(link="plugins:netbox_auspex:audits", link_text="Exports d'audit",
                   permissions=["ipam.view_ipaddress"]),
)
