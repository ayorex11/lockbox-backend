from django.urls import path

from . import recipient_views, views

urlpatterns = [
    path("files/", views.FileInitView.as_view()),
    path("files/<uuid:pk>/complete/", views.FileCompleteView.as_view()),
    path("links/", views.LinkListCreateView.as_view()),
    path("links/<slug:pk>/", views.LinkDetailView.as_view()),
    path("links/<slug:pk>/events/", views.LinkEventsView.as_view()),
    path("links/<slug:pk>/revoke/", views.LinkRevokeView.as_view()),
    path("s/<slug:token>/", recipient_views.LinkMetaView.as_view()),
    path("s/<slug:token>/claim/", recipient_views.LinkClaimView.as_view()),
    path("s/<slug:token>/reissue/", recipient_views.LinkReissueView.as_view()),
]
