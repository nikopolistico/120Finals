from django.urls import path
from . import views

urlpatterns = [
    path('payment/', views.payment_view, name='payment_view'),  # Your payment view
    path('api/send-message/', views.send_message, name='send_message'),  # Your send_message API endpoint
]
