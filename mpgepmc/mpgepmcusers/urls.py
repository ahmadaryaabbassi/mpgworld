# mpgepmcusers/urls.py
from django.urls import path
from . import views

app_name = 'mpgepmcusers'

urlpatterns = [
    path('', views.index, name='index'),
    path('signup/', views.signup, name='signup'),
    path('signin/', views.signin, name='signin'),
    path('signout/', views.signout, name='signout'),
    path('home/', views.home, name='home'),

    # AJAX validation
    path('ajax/validate-field/', views.ajax_validate_field, name='ajax_validate_field'),

    # signup OTP
    path('otp/', views.otp_verify, name='otp_verify'),
    path('otp/resend/', views.resend_otp, name='resend_otp'),

    # password reset link flow
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uuid:token>/', views.reset_password, name='reset_password'),

    # change password
    path('change-password/', views.change_password, name='change_password'),
]
