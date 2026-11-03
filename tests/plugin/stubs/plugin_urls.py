"""URL de test, nommées comme dans NetBox (home, login, logout, plugins:...)."""
from django.contrib.auth import logout
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import include, path


def home(request):
    return HttpResponse("accueil")


def page(request):
    return HttpResponse("page protégée")


def sso_fail(request):
    from social_core.exceptions import AuthForbidden
    raise AuthForbidden("backend")


def other_fail(request):
    raise ValueError("autre erreur")


def login_view(request):
    return HttpResponse("connexion")


def logout_view(request):
    logout(request)
    return HttpResponseRedirect("/login/")


plugin_patterns = [path("auspex/", include(("netbox_auspex.urls", "netbox_auspex")))]

urlpatterns = [
    path("", home, name="home"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("ipam/ip-addresses/", page),
    path("api/ipam/ip-addresses/", page),
    path("plugins/", include((plugin_patterns, "plugins"))),
    path("oauth/login/<str:backend>/", page),
    path("oauth/complete/refus/", sso_fail),
    path("autre-erreur/", other_fail),
]
