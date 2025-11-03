# login/urls.py
from django.urls import path
from .views import SignupView, VerifyOTPView, LoginView, ResendOTPView

urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    path("resend-otp/", ResendOTPView.as_view(), name="resend-otp"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("login/", LoginView.as_view(), name="login"),
]
