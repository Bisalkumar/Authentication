from django.urls import path
from app.views import signup, login_view, logout_view, activate
from app.views import ResetPasswordView
from .views import CustomPasswordResetCompleteView, CustomPasswordResetConfirmView
from .views import user_ui, admin_ui

urlpatterns = [
    path("signup/", signup, name='signup'),
    path("login/", login_view, name='login'),
    path("logout/", logout_view, name='logout'),
    path('activate/<str:uidb64>/<str:token>/', activate, name='activate'),
    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         CustomPasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'),
         name='password_reset_confirm'),
    path('password-reset-complete/',
         CustomPasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),
         name='password_reset_complete'),           
    path('user_ui/', user_ui , name='user_ui'),
    path('admin_ui/', admin_ui , name='admin_ui'),
]