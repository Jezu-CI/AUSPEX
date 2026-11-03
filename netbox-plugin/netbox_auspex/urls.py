from django.urls import path

from . import audits, carte, dashboard, mfa

urlpatterns = [
    path("mfa/", mfa.verify_view, name="mfa"),
    path("mfa/setup/", mfa.setup_view, name="mfa_setup"),
    path("mfa/setup/choisir/", mfa.switch_view, name="mfa_switch"),
    path("mfa/cles/", mfa.keys_view, name="mfa_keys"),
    path("carte-a-puce/", carte.card_login_view, name="carte_a_puce"),
    path("ecarts/", dashboard.findings_view, name="findings"),
    path("carte/", dashboard.map_view, name="map"),
    path("carte/donnees/", dashboard.map_data_view, name="map_data"),
    path("audits/", audits.audits_view, name="audits"),
    path("audits/<str:name>", audits.audit_download_view, name="audit_download"),
]
