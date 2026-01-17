from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import generate_token
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# ================= SIGNUP =================

def signin(request):
    if request.method == "POST":
        email = request.POST['email']
        username = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        if password1 != password2:
            messages.warning(request, "Password is not Matched")
            return render(request, 'signin.html')

        # check email already exists
        if User.objects.filter(email=email).exists():
            messages.info(request, "Email Already Registered")
            return render(request, 'signin.html')

        # check username already exists
        if User.objects.filter(username=username).exists():
            messages.info(request, "Username Already Exists")
            return render(request, "signin.html")

        user = User.objects.create_user(username=username, email=email, password=password1)
        user.is_active = False
        user.save()

        email_subject = "Activate Your Account"
        message = render_to_string('activate.html', {
            'user': user,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })

        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
        )
        email_message.send()

        messages.success(request, "Activate Your Account using the email link")
        return redirect('/auth/login')

    return render(request, "signin.html")



# ================= ACTIVATE ACCOUNT =================

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account Activated Successfully")
            return redirect("/auth/login")

        return render(request, "activatefail.html")



# ================= LOGIN (EMAIL LOGIN) =================

def user_login(request):
    if request.method == "POST":

        email = request.POST.get('email')
        password = request.POST.get('password1')

        users = User.objects.filter(email=email)

        if not users.exists():
            messages.error(request, "Email not registered")
            return redirect("/auth/login/")

        # Check each user because email is not unique in Django default model
        for u in users:
            user = authenticate(username=u.username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    messages.success(request, "Login Success")
                    return redirect("/")
                else:
                    messages.error(request, "Please activate your account")
                    return redirect("/auth/login/")

        messages.error(request, "Invalid password")
        return redirect("/auth/login/")

    return render(request, "login.html")



# ================= LOGOUT =================

def user_logout(request):
    logout(request)
    messages.info(request, "Logout Success")
    return redirect("/auth/login/")



# ================= RESET PASSWORD - REQUEST =================

class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)

        if user.exists():

            email_subject = 'Reset Your Password'
            message = render_to_string('reset-user-password.html', {
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })

            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email]
            )
            email_message.send()

            messages.info(request, "Password reset link sent")
            return render(request, 'request-reset-email.html')

        messages.error(request, "User not found")
        return render(request, 'request-reset-email.html')



# ================= RESET PASSWORD - SET NEW =================

class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link Invalid")
                return render(request, 'request-reset-email.html')

        except DjangoUnicodeDecodeError:
            messages.error(request, "Invalid link")
            return render(request, 'request-reset-email.html')

        return render(request, 'set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        password = request.POST['pass1']
        confirm_password = request.POST['pass2']

        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'set-new-password.html', context)

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            user.set_password(password)
            user.save()

            messages.success(request, "Password Reset Success")
            return redirect('/auth/login/')

        except DjangoUnicodeDecodeError:
            messages.error(request, "Something went wrong")
            return render(request, 'set-new-password.html', context)

        return render(request, 'set-new-password.html', context)
