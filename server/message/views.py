import base64
import json
import logging
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from cryptography.fernet import Fernet
from django.conf import settings
from django.shortcuts import render, redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Message
from .serializers import MessageSerializer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import requests
from .forms import AdminLoginForm


f = Fernet(settings.ENCRYPT_KEY)
# Setup logging
logger = logging.getLogger(__name__)

# API view for receiving messages

class ReceiveMessageView(APIView):
   def post(self, request, *args, **kwargs):
        try:
            # Get the base64-encoded message from the request body
            message_base64 = request.data.get('message')

            if not message_base64:
                return Response({'error': 'No message provided'}, status=status.HTTP_400_BAD_REQUEST)

            # Decode from base64
            try:
                message_encrypted = base64.b64decode(message_base64)
            except base64.binascii.Error:
                return Response({'error': 'Invalid base64 encoding'}, status=status.HTTP_400_BAD_REQUEST)

            # Decrypt the message
            try:
                message_bytes = f.decrypt(message_encrypted)
            except Exception:
                return Response({'error': 'Decryption failed'}, status=status.HTTP_400_BAD_REQUEST)

            # Decode the decrypted message back to a dictionary
            try:
                message_data = json.loads(message_bytes.decode('utf-8'))
            except json.JSONDecodeError:
                return Response({'error': 'Invalid JSON format in decrypted message'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract content, sender, and payment
            content = message_data.get('content')
            sender = message_data.get('sender')
            payment = message_data.get('payment')

            if not content or not sender:
                return Response({'error': 'Missing content or sender'}, status=status.HTTP_400_BAD_REQUEST)

            encrypted_content = f.encrypt(content.encode('utf-8'))

# Convert encrypted content to base64-encoded string
            encrypted_content_base64 = base64.b64encode(encrypted_content).decode('utf-8')

                # Save the base64-encoded encrypted content to the database
            message = Message.objects.create(content=encrypted_content_base64, sender=sender, payment=payment)

            # Return the response
            return Response({
                'message': 'Message received successfully',
                'content': content,  # Return original content for confirmation
                'sender': sender,
                'payment': payment,
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'Unexpected error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class GetMessagesView(APIView):
    def get(self, request, *args, **kwargs):
        # Get all messages from the database
        messages = Message.objects.all()

        decrypted_messages = []
        for message in messages:
            try:
                # Decode the base64-encoded content stored in the database
                message_encrypted = base64.b64decode(message.content)
                
                # Decrypt the message content using the provided encryption key
                decrypted_bytes = f.decrypt(message_encrypted)

                # Decode the decrypted bytes back to a string
                decrypted_content = decrypted_bytes.decode('utf-8')

                # Append the decrypted content and other message data
                decrypted_message = {
                    'id': message.id,
                    'content': decrypted_content,  # Decrypted content
                    'sender': message.sender,
                    'payment': message.payment,
                    'created_at': message.created_at
                }
                decrypted_messages.append(decrypted_message)

            except Exception as e:
                # In case decryption fails, return a placeholder message
                decrypted_messages.append({
                    'id': message.id,
                    'content': "fail",  # Placeholder for failed decryption
                    'sender': message.sender,
                    'payment': message.payment
                })
                logger.error(f"Decryption failed for message {message.id}: {str(e)}")

        # Return the decrypted messages in the response
        return Response(decrypted_messages, status=status.HTTP_200_OK)


# Render the template with the messages from the database


# API view to delete a specific message
class DeleteMessageView(APIView):
    def delete(self, request, *args, **kwargs):
        message_id = kwargs.get('pk')  # Get message ID from the URL
        try:
            message = Message.objects.get(pk=message_id)  # Find message by ID
            message.delete()  # Delete the message
            return Response({'message': 'Message deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)
        except Message.DoesNotExist:
            return Response({'error': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)


def admin_login(request):
    if request.method == 'POST':
        form = AdminLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            
            # Check if user exists and is a superuser
            if user is not None and user.is_superuser:
                print(f"User {username} logged in successfully.")  # Printing successful login
                login(request, user)
                return redirect('admin_dashboard')  # Redirect to admin dashboard
            else:
                print("Invalid login credentials or not a superuser.")
                form.add_error(None, 'Invalid login credentials or you are not an admin')
        else:
            print("Form is not valid.")
            print(form.errors)  # This will print detailed form errors in the console
    else:
        form = AdminLoginForm()

    return render(request, 'admin_login.html', {'form': form})

@login_required
def admin_dashboard(request):
  
    messages = Message.objects.all()  # Example logic to get messages (change as needed)
    
    return render(request, 'admin_dashboard.html', {'messages': messages})


def logout_view(request):
    logout(request)
    return redirect('admin_login')  #