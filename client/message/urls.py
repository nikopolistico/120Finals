from django.urls import path
from . import views

urlpatterns = [
    path('api/send-message/', views.send_message, name='send_message'),  # Your send_message API endpoint
    path('signup/', views.signup_view, name='signup'),
    path('', views.login_view, name='login'),  # Correct URL pattern for login
    path('payment/', views.dashboard_view, name='payment'),  # URL for the payment page
    path('logout/', views.logout_view, name='logout'),
    path('api/receive-payment-confirmation/', views.receive_payment_confirmation, name='receive_payment_confirmation'),
]
