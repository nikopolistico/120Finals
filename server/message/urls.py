
from django.urls import path
from . import views

urlpatterns = [
    # API views for messages
    path('api/receive-message/', views.ReceiveMessageView.as_view(), name='receive_message'),
    path('api/get-messages/', views.GetMessagesView.as_view(), name='get-messages'),
    path('api/delete-message/<int:pk>/', views.DeleteMessageView.as_view(), name='delete-message'),
    path('', views.admin_login, name='admin_login'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('logout/', views.logout_view, name='logout'),
]
