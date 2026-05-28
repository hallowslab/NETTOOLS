from django.urls import path
from . import views

app_name = "nettools"

urlpatterns = [
    path("", views.index, name="nettools_home"),
    path("whereis/", views.whereis, name="whereis"),
    path("whois/", views.whois, name="whois"),
    path("spf/", views.spf, name="spf"),
    path("propagation/", views.propagation, name="propagation"),
]
