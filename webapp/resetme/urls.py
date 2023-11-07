from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("success/", views.success, name="success"),
    path("verify/", views.verify_phone, name="verify"),
    path("domain/", views.domain_choise, name="domain"),
]