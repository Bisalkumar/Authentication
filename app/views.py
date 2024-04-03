from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.views import PasswordResetView, PasswordResetCompleteView, PasswordResetConfirmView
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect, render, get_object_or_404
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from app.forms import UseRegisterForm, UserUpdateForm
from app.models import Dashboard_User

User = settings.AUTH_USER_MODEL




# email verfication
class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return str(user.pk) + str(timestamp) + str(user.is_active)


account_activation_token = AccountActivationTokenGenerator()


def signup(request):
    new_user = None
    if request.method == 'POST':
        form = UseRegisterForm(request.POST or None)
        if form.is_valid():
            new_user = form.save(commit=False)
            new_user.is_active = False
            new_user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f"Hey {username}, your account was created successfully.")

            current_site = get_current_site(request)
            mail_subject = 'Activation link has been sent to your email id'
            message = render_to_string('acc_active_email.html', {
                'user': new_user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(new_user.pk)),
                'token': account_activation_token.make_token(new_user),
            })
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.content_subtype = 'html'
            email.send()
            messages.success(request,f"Please confirm your email address to complete the registration.<a href='{('https://mail.google.com/')}'>Click here</a> to go to Gmail.")
            return redirect('app:signup')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{error}')
            return render(request, 'signup.html', {'form': form})
    else:
        form = UseRegisterForm()
    context = {'form': form}
    return render(request, 'signup.html', context)


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        print(user)
        if user is not None:
            login(request, user)
            request.session['username'] = user.username
            return redirect('home:index')
        else:
            messages.info(request, 'Invalid Credentials')
            return redirect('app:login')
    else:
        return render(request, 'login.html')


def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out.")

    return redirect("home:index")


def home(request):
    return render(request, "home.html")


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        # Activate the user account
        user.is_active = True
        user.save()
        new = Dashboard_User(user=user)
        new.save()
        # Redirect to the login page
        return redirect('app:login')
    else:
        return HttpResponse('Activation link is invalid!')


class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'password_reset.html'
    email_template_name = 'password_reset_email.html'
    # subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the addre ss you registered with, and check your spam folder."
    success_url = reverse_lazy('app:login')


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'  # Set your custom template name
    # Override success_url attribute
    success_url = reverse_lazy('app:password_reset_complete')


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'password_reset_complete.html'  # Set your custom template name
    # Override success_url attribute
    success_url = 'app:login'










@login_required(login_url="/app/login/")
@transaction.atomic
def user_ui(request):
    if request.method == "GET":
        auser = request.user
        if request.user.is_authenticated:
            if auser.is_staff == True:
                return redirect("/admin")
            else:
                # username = request.session['username']
                user = User.objects.get(username=request.user.username)
                if not Dashboard_User.objects.filter(user_id=user.id).exists():
                    dashboard_user, created = Dashboard_User.objects.get_or_create(user=auser)
                    dashboard_user.save()
                dash_user = Dashboard_User.objects.get(user_id=user.id)
                # all_courses = Course.objects.all()
                enrolled_courses = dash_user.enrolled_courses.filter(status="active")
                return render(
                    request,
                    "dashboard.html",
                    {
                        "user": user,
                        "dash_user": dash_user,
                        "enrolled_courses": enrolled_courses,
                    },
                )
        else:
            return redirect("app:login")
    if request.method == "POST":
        user_profile = Dashboard_User.objects.get(user=request.user)

    if request.method == "POST":
      #get from frontend
        first_name = request.POST.get("first_name")
        middle_name = request.POST.get("middle_name")
        last_name = request.POST.get("last_name")
        mobile_number = request.POST.get("mobile_number")
        college_name = request.POST.get("college_name")
        graduation_year = request.POST.get("graduation_year")
        bio = request.POST.get("mobile_number")
        # Update user details
        user_profile.fname = first_name
        user_profile.mname = middle_name
        user_profile.lname = last_name
        user_profile.mobilenumber = mobile_number
        user_profile.collegename = college_name
        user_profile.graduation_year = graduation_year
        user_profile.bio = bio
        # Save changes
        user_profile.save()
        # messages.success(request, "Profile updated successfully")
        return redirect("app:user_ui")
    return render(request, "dashboard.html", {"user": request.user})


def admin_ui(request):
    if request.method == "GET":
        if request.user.is_authenticated:
            auser = request.user
            if auser.is_staff == True:
                return redirect("home:index")
            else:
                return redirect("/admin")
        else:
            return redirect("home:index")