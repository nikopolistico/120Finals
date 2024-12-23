import base64
import json
import logging
from cryptography.fernet import Fernet
from django.conf import settings
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Message
from .serializers import MessageSerializer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import requests

# Setup logging
logger = logging.getLogger(__name__)

# Initialize Fernet encryption key
f = Fernet(settings.ENCRYPT_KEY)  # Make sure ENCRYPT_KEY is properly set in your settings

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
            except base64.binascii.Error as e:
                return Response({'error': 'Invalid base64 encoding'}, status=status.HTTP_400_BAD_REQUEST)

            # Decrypt the message
            try:
                message_bytes = f.decrypt(message_encrypted)
            except Exception as e:
                return Response({'error': 'Decryption failed'}, status=status.HTTP_400_BAD_REQUEST)

            # Decode the decrypted message back to a dictionary
            try:
                message_data = json.loads(message_bytes.decode('utf-8'))
            except json.JSONDecodeError:
                return Response({'error': 'Invalid JSON format'}, status=status.HTTP_400_BAD_REQUEST)

            content = message_data.get('content')
            sender = message_data.get('sender')
            payment = message_data.get('payment')

            if not content or not sender:
                return Response({'error': 'Missing content or sender'}, status=status.HTTP_400_BAD_REQUEST)

            # Encrypt the content before saving to the database (store the encrypted content)
            encrypted_content = f.encrypt(content.encode('utf-8')).decode('utf-8')

            # Create a new Message object and save it to the database
            message = Message.objects.create(content=encrypted_content, sender=sender, payment=payment)

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
                # Decrypt the content of each message
                decrypted_content = f.decrypt(message.content.encode('utf-8')).decode('utf-8')
                # Append decrypted content and other message data
                decrypted_message = {
                    'id': message.id,
                    'content': decrypted_content,  # Decrypted content
                    'sender': message.sender,
                    'payment': message.payment
                }
                decrypted_messages.append(decrypted_message)
            except Exception as e:
                # If decryption fails, log the error and append a failed message
                decrypted_messages.append({
                    'id': message.id,
                    'content': "Decryption failed",  # Placeholder for failed decryption
                    'sender': message.sender,
                    'payment': message.payment
                })

        # Return the decrypted messages
        return Response(decrypted_messages, status=status.HTTP_200_OK)

# Render the template with the messages from the database
def index(request):
    # Fetch messages from the database
    messages = Message.objects.all()
    
    # Render the 'index.html' template and pass the messages as context
    return render(request, 'index.html', {'messages': messages})


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
        
def send_payment_confirmation(request):
    if request.method == 'POST':
        try:
            # Get the JSON data from the body of the request
            data = json.loads(request.body)
            content = data.get('content')  # The message content

            if content:
                # Send the message to the target server at 127.0.0.1:8000
                api_url = 'http://127.0.0.1:8000/api/send-message/'  # Target server URL
                payload = {'content': content}

                # Send the POST request to the target server
                response = requests.post(api_url, json=payload)

                if response.status_code == 201:
                    return JsonResponse({"success": True, "message": "Payment confirmation sent to the target server."})
                else:
                    return JsonResponse({"success": False, "message": "Failed to send message to target server."}, status=500)
            else:
                return JsonResponse({"success": False, "message": "No message content provided."}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"success": False, "message": "Invalid JSON format."}, status=400)

    return JsonResponse({"success": False, "message": "Invalid request method."}, status=400)
