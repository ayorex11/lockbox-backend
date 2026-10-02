from django.urls import path

from . import views

urlpatterns = [
    path("register", views.RegisterView.as_view()),
    path("verify-email", views.VerifyEmailView.as_view()),
    path("resend-verification", views.ResendVerificationView.as_view()),
    path("forgot-password", views.ForgotPasswordView.as_view()),
    path("reset-password", views.ResetPasswordView.as_view()),
    path("login", views.LoginView.as_view()),
    path("refresh", views.RefreshView.as_view()),
    path("logout", views.LogoutView.as_view()),
    path("me", views.MeView.as_view()),
]
