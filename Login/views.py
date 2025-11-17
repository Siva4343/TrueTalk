# login/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .models import OTP, PendingUser
from .serializers import SignupSerializer, VerifyOTPSerializer, LoginSerializer
import random
from django.core.mail import send_mail
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.authtoken.models import Token
from django.db import IntegrityError

def generate_otp():
    return str(random.randint(100000, 999999)).zfill(6)

class SignupView(APIView):
    """
    Accepts first_name, last_name, email, password.
    Creates/updates PendingUser and sends OTP to email.
    """
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        email = data["email"].lower()

        # If a real user with this email exists, block signup
        if User.objects.filter(username=email).exists():
            return Response({"message": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        # Hash password for safe storage until verification
        password_hashed = make_password(data["password"])

        # Create or update PendingUser
        pending, created = PendingUser.objects.update_or_create(
            email=email,
            defaults={
                "first_name": data["first_name"],
                "last_name": data["last_name"],
                "password_hash": password_hashed,
            }
        )

        # Generate OTP and save
        otp_code = generate_otp()
        OTP.objects.create(email=email, code=otp_code)

        # Send OTP via email
        try:
            send_mail(
                subject="Your OTP Code",
                message=f"Your OTP code is {otp_code}. It expires in 5 minutes.",
                from_email=None,  # uses DEFAULT_FROM_EMAIL if None
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as e:
            # In development with console backend this won't error; for SMTP show friendly message
            print("Error sending email:", e)
            return Response({"message": "Failed to send OTP email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "OTP sent to email. Please verify.", "email": email}, status=status.HTTP_200_OK)


class ResendOTPView(APIView):
    """
    Resend OTP for a pending user.
    """
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"message": "Email required."}, status=status.HTTP_400_BAD_REQUEST)
        email = email.lower()
        try:
            if not PendingUser.objects.filter(email=email).exists():
                return Response({"message": "No pending signup for this email."}, status=status.HTTP_400_BAD_REQUEST)

            otp_code = generate_otp()
            OTP.objects.create(email=email, code=otp_code)
            send_mail(
                subject="Your OTP Code - Resend",
                message=f"Your OTP code is {otp_code}. It expires in 5 minutes.",
                from_email=None,
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({"message": "OTP resent."}, status=status.HTTP_200_OK)
        except Exception as e:
            print("ResendOTP error:", e)
            return Response({"message": "Failed to resend OTP."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].lower()
        otp_input = str(serializer.validated_data["otp"]).strip()

        try:
            otp_obj = OTP.objects.filter(email=email).latest("created_at")
        except OTP.DoesNotExist:
            return Response({"message": "Invalid OTP."}, status=400)

        # OTP match
        if otp_obj.code != otp_input:
            return Response({"message": "Invalid OTP."}, status=400)

        # OTP expiry
        if otp_obj.is_expired():
            return Response({"message": "OTP expired."}, status=400)

        try:
            pending = PendingUser.objects.get(email=email)
        except PendingUser.DoesNotExist:
            return Response({"message": "No pending signup."}, status=400)

        # Create user
        user = User.objects.create(
            username=email,
            first_name=pending.first_name,
            last_name=pending.last_name,
            email=email,
            password=pending.password_hash
        )

        # 🔥 Token create (this was failing earlier)
        try:
            token, _ = Token.objects.get_or_create(user=user)
        except Exception as e:
            print("TOKEN ERROR:", e)
            return Response({"message": "Token generation failed."}, status=500)

        # Cleanup
        pending.delete()
        OTP.objects.filter(email=email).delete()

        return Response({"message": "OTP verified", "token": token.key}, status=201)


class LoginView(APIView):
    """
    Login with email & password. Returns Token on success.
    """
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data
        email = data["email"].lower()
        password = data["password"]

        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            return Response({"message": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({"message": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "message": "Login successful."}, status=status.HTTP_200_OK)
