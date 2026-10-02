from django.urls import path

from . import views

urlpatterns = [
    path("overview/", views.OverviewView.as_view()),
    path("timeseries/", views.TimeseriesView.as_view()),
    path("top-users/", views.TopUsersView.as_view()),
    path("security/", views.SecurityView.as_view()),
]
