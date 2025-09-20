# mpgepmcusers/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth import login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.utils import timezone
from django.urls import reverse
from .forms import SignupForm, ForgotPasswordForm, ResetPasswordForm, ChangePasswordForm
from .models import CustomUser, OTP, PasswordResetToken
from .validators import valid_name, valid_mobile, valid_email_domain, valid_password, valid_age
import random

OTP_TTL_MINUTES = 30
RESET_LINK_TTL_HOURS = 1


# ------------------ Helper: signup OTP creation & reuse rules ------------------
def _get_or_create_signup_otp(user):
    """
    Returns (otp_obj, created_bool).
    Behavior:
      - If the latest OTP (any) was created less than 30 minutes ago -> do NOT create a new one; return latest, False.
      - Otherwise create a new OTP (invalidate any active ones) and send email -> return new otp, True.
    This satisfies: "Never send new OTP while previous is not expired" and
    "if user tried 3 wrong attempts OTP marked invalid but still block new OTP until previous TTL."
    """
    latest = OTP.objects.filter(user=user).order_by('-created_at').first()
    if latest:
        expiry_time = latest.created_at + timezone.timedelta(minutes=OTP_TTL_MINUTES)
        if timezone.now() < expiry_time:
            # previous OTP not yet expired; do not create new one.
            return latest, False

    # create new
    OTP.objects.filter(user=user, is_active=True).update(is_active=False)
    code = f"{random.randint(100000, 999999)}"
    otp = OTP.objects.create(user=user, code=code, is_active=True)
    send_mail(
        "Your MPGEPMC Signup OTP",
        f"Your OTP code is {code}. It is valid for {OTP_TTL_MINUTES} minutes.",
        None,
        [user.email],
    )
    return otp, True


# ------------------ Index ------------------
def index(request):
    if request.user.is_authenticated:
        return redirect('mpgepmcusers:home')
    return render(request, 'mpgepmcusers/index.html')


# ------------------ Signup ------------------
def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            username = cd['email'].split('@')[0]
            base = username
            i = 1
            while CustomUser.objects.filter(username=username).exists():
                username = f"{base}{i}"
                i += 1
            user = CustomUser.objects.create(
                username=username,
                email=cd['email'],
                first_name=cd['first_name'],
                middle_name=cd.get('middle_name') or '',
                last_name=cd['last_name'],
                dob=cd['dob'],
                gender=cd['gender'],
                gender_other_text=cd.get('gender_other_text', ''),
                mobile=cd['mobile'],
                is_active=True,
                is_verified=False,
            )
            user.set_password(cd['password'])
            user.save()

            request.session['pending_user_email'] = user.email
            _get_or_create_signup_otp(user)  # will send if none or expired
            return redirect('mpgepmcusers:otp_verify')
    else:
        form = SignupForm()
    return render(request, 'mpgepmcusers/signup.html', {'form': form})


# ------------------ AJAX field validation ------------------
def ajax_validate_field(request):
    field = request.POST.get('field')
    value = request.POST.get('value', '').strip()
    if not field:
        return JsonResponse({'valid': False, 'error': 'No field provided.'})

    if field in ['first_name', 'last_name']:
        ok = valid_name(value)
        return JsonResponse({'valid': ok, 'error': '' if ok else f"Invalid {field.replace('_',' ')}."})
    if field == 'email':
        if not valid_email_domain(value):
            return JsonResponse({'valid': False, 'error': 'Email domain not allowed.'})
        if CustomUser.objects.filter(email__iexact=value).exists():
            return JsonResponse({'valid': False, 'error': 'Email already registered.'})
        return JsonResponse({'valid': True, 'error': ''})
    if field == 'mobile':
        if not valid_mobile(value):
            return JsonResponse({'valid': False, 'error': 'Invalid mobile number.'})
        if CustomUser.objects.filter(mobile=value).exists():
            return JsonResponse({'valid': False, 'error': 'Mobile already registered.'})
        return JsonResponse({'valid': True, 'error': ''})
    if field == 'dob':
        from datetime import datetime
        try:
            d = datetime.strptime(value, '%Y-%m-%d').date()
            if not valid_age(d):
                return JsonResponse({'valid': False, 'error': 'Age must be 12–150 years.'})
            return JsonResponse({'valid': True, 'error': ''})
        except Exception:
            return JsonResponse({'valid': False, 'error': 'Invalid date format.'})
    if field == 'password':
        ok, msg = valid_password(value)
        return JsonResponse({'valid': ok, 'error': '' if ok else msg})
    return JsonResponse({'valid': True, 'error': ''})


# ------------------ Signup OTP verify page ------------------
def otp_verify(request):
    email = request.session.get('pending_user_email')
    user = CustomUser.objects.filter(email__iexact=email).first() if email else None
    latest_otp = OTP.objects.filter(user=user).order_by('-created_at').first() if user else None

    # compute remaining seconds for countdown if latest exists
    otp_remaining_seconds = None
    if latest_otp:
        expiry_time = latest_otp.created_at + timezone.timedelta(minutes=OTP_TTL_MINUTES)
        if expiry_time > timezone.now():
            otp_remaining_seconds = int((expiry_time - timezone.now()).total_seconds())

    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if not user or not latest_otp or latest_otp.expired():
            messages.error(request, "OTP expired or not found. You may request a new OTP after expiry.")
            return redirect('mpgepmcusers:otp_verify')

        if latest_otp.attempts >= 3:
            # lock it (mark invalid) — but still block new ones until TTL passes (we use created_at to block)
            latest_otp.mark_invalid()
            messages.error(request, "OTP locked due to 3 incorrect attempts. Wait until it expires to request a new one.")
            return redirect('mpgepmcusers:otp_verify')

        if code == latest_otp.code:
            latest_otp.mark_invalid()
            user.is_verified = True
            user.save()
            messages.success(request, "Verification successful. Please sign in.")
            request.session.pop('pending_user_email', None)
            return redirect('mpgepmcusers:signin')
        else:
            latest_otp.attempts += 1
            latest_otp.save()
            remaining_tries = max(0, 3 - latest_otp.attempts)
            messages.error(request, f"Incorrect OTP. {remaining_tries} attempt(s) left.")
            return redirect('mpgepmcusers:otp_verify')

    return render(request, 'mpgepmcusers/otp_verify.html', {
        'user': user,
        'otp': latest_otp,
        'otp_remaining_seconds': otp_remaining_seconds,
    })


def resend_otp(request):
    """
    When user clicks resend:
      - If there is a previous OTP created less than 30 minutes ago => DON'T send; show remaining time.
      - Otherwise create new OTP and send.
    """
    email = request.session.get('pending_user_email')
    user = CustomUser.objects.filter(email__iexact=email).first() if email else None
    if not user:
        messages.error(request, "No pending user to resend OTP for.")
        return redirect('mpgepmcusers:signup')

    latest = OTP.objects.filter(user=user).order_by('-created_at').first()
    if latest:
        expiry_time = latest.created_at + timezone.timedelta(minutes=OTP_TTL_MINUTES)
        if expiry_time > timezone.now():
            remaining_seconds = int((expiry_time - timezone.now()).total_seconds())
            minutes, seconds = divmod(remaining_seconds, 60)
            messages.warning(request, f"A previous OTP is still valid. Please wait {minutes}m {seconds}s.")
            return redirect('mpgepmcusers:otp_verify')

    # no unexpired previous OTP => create and send
    otp = _get_or_create_signup_otp(user)  # since no valid previous, this will create and send
    # _get_or_create_signup_otp returns (otp, created) but here it's fine
    messages.success(request, "A new OTP has been sent to your email.")
    return redirect('mpgepmcusers:otp_verify')


# ------------------ Signin ------------------

# ------------------ Signin ------------------
def signin(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        user = CustomUser.objects.filter(email__iexact=email).first()

        # Case 1: email not registered
        if not user:
            messages.error(request, "Your email is not associated with any account. Please try with correct credentials.")
            return redirect('mpgepmcusers:signin')

        # Case 2: registered but not verified
        if not user.is_verified:
            if user.check_password(password):
                # password correct, but not verified
                request.session['pending_user_email'] = user.email
                _get_or_create_signup_otp(user)
                messages.error(request, "Your account is not verified. Please verify with the OTP sent to your email before you can sign in.")
                return redirect('mpgepmcusers:otp_verify')
            else:
                # password incorrect & not verified
                messages.error(request, "Your account is not verified and you entered invalid credentials.")
                return redirect('mpgepmcusers:signin')

        # Case 3: registered & verified
        if user.is_verified:
            if user.check_password(password):
                login(request, user)
                return redirect('mpgepmcusers:home')
            else:
                messages.error(request, "You are entering invalid credentials.")
                return redirect('mpgepmcusers:signin')

    return render(request, 'mpgepmcusers/signin.html')




# ------------------ Home & signout ------------------
@login_required
def home(request):
    return render(request, 'mpgepmcusers/home.html', {'full_name': request.user.full_with_initials()})


def signout(request):
    logout(request)
    return redirect('mpgepmcusers:index')


# ------------------ Forgot password (link-based) ------------------

# ------------------ Forgot password (link-based) ------------------
def forgot_password(request):
    """
    Only send password reset link if:
      - user exists
      - is active
      - is verified via signup OTP
    Otherwise block silently.
    """
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email'].lower()
            user = CustomUser.objects.filter(email__iexact=email).first()

            if not user:
                messages.error(request, "No account found with this email.")
                return redirect('mpgepmcusers:forgot_password')

            if not user.is_active or not user.is_verified:
                messages.error(request, "This account is not active or not verified. Cannot reset password.")
                return redirect('mpgepmcusers:forgot_password')

            latest_token = PasswordResetToken.objects.filter(user=user).order_by('-created_at').first()
            if latest_token:
                expiry_time = latest_token.created_at + timezone.timedelta(hours=RESET_LINK_TTL_HOURS)
                if expiry_time > timezone.now():
                    remaining_seconds = int((expiry_time - timezone.now()).total_seconds())
                    minutes, seconds = divmod(remaining_seconds, 60)
                    messages.warning(request, f"A password reset link was already sent. Wait {minutes}m {seconds}s or use the existing link.")
                    return render(request, 'mpgepmcusers/forgot_password.html', {
                        'form': form,
                        'token_remaining_seconds': remaining_seconds,
                        'existing_token': latest_token,
                    })

            # create new token & send
            token_obj = PasswordResetToken.objects.create(user=user)
            reset_path = reverse('mpgepmcusers:reset_password', args=[str(token_obj.token)])
            reset_link = request.build_absolute_uri(reset_path)
            send_mail(
                "MPGEPMC Password Reset",
                f"Click the link below to reset your password (valid for {RESET_LINK_TTL_HOURS} hour):\n\n{reset_link}",
                None,
                [user.email],
            )
            messages.success(request, "Password reset link sent to your email.")
            return redirect('mpgepmcusers:signin')
    else:
        form = ForgotPasswordForm()
    return render(request, 'mpgepmcusers/forgot_password.html', {'form': form})



# ------------------ Reset password view (token link) ------------------
def reset_password(request, token):
    token_obj = get_object_or_404(PasswordResetToken, token=token)
    # block if expired or already used (and keep message)
    if token_obj.expired():
        messages.error(request, "Reset link expired. Request a new one.")
        return redirect('mpgepmcusers:forgot_password')
    if token_obj.is_used:
        messages.error(request, "This reset link has already been used. Request a new one.")
        return redirect('mpgepmcusers:forgot_password')

    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            new_pw = form.cleaned_data['password']
            user = token_obj.user
            user.set_password(new_pw)
            user.save()
            token_obj.is_used = True
            token_obj.save()
            messages.success(request, "Password has been reset. Please sign in.")
            return redirect('mpgepmcusers:signin')
    else:
        form = ResetPasswordForm()

    # compute remaining seconds for UI (optional)
    expiry_time = token_obj.created_at + timezone.timedelta(hours=RESET_LINK_TTL_HOURS)
    remaining_seconds = max(0, int((expiry_time - timezone.now()).total_seconds()))
    return render(request, 'mpgepmcusers/reset_password.html', {'form': form, 'remaining_seconds': remaining_seconds})


# ------------------ Change password (authenticated) ------------------
@login_required
def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            new_pw = form.cleaned_data['new_password']
            request.user.set_password(new_pw)
            request.user.save()
            messages.success(request, "Password changed successfully. Please log in again.")
            logout(request)
            return redirect('mpgepmcusers:signin')
    else:
        form = ChangePasswordForm(request.user)
    return render(request, 'mpgepmcusers/change_password.html', {'form': form})
