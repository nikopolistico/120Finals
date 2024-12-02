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

# Setup logging
logger = logging.getLogger(__name__)

# Initialize Fernet encryption key
f = Fernet(settings.ENCRYPT_KEY)  # Make sure ENCRYPT_KEY is properly set in your settings

# API view for receiving messages
class ReceiveMessageView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            # Get the base64-encoded message from the request body
            message_base64 = request.data.get('message')  # Get from the POST body

            if not message_base64:
                return Response({'error': 'No message provided'}, status=status.HTTP_400_BAD_REQUEST)

            # Decode from base64
            try:
                message_encrypted = base64.b64decode(message_base64)
            except base64.binascii.Error as e:
                logger.error(f"Base64 decode error: {e}")
                return Response({'error': 'Invalid base64 encoding'}, status=status.HTTP_400_BAD_REQUEST)

            # Decrypt the message
            try:
                message_bytes = f.decrypt(message_encrypted)
            except Exception as e:
                logger.error(f"Decryption error: {e}")
                return Response({'error': 'Decryption failed'}, status=status.HTTP_400_BAD_REQUEST)

            # Decode the decrypted message back to a dictionary
            try:
                message_data = json.loads(message_bytes.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                return Response({'error': 'Invalid JSON format'}, status=status.HTTP_400_BAD_REQUEST)

            content = message_data.get('content')
            sender = message_data.get('sender')
            payment = message_data.get('payment')

            if not content or not sender:
                return Response({'error': 'Missing content or sender'}, status=status.HTTP_400_BAD_REQUEST)

            # Encrypt the content before saving to the database
            encrypted_content = f.encrypt(content.encode('utf-8')).decode('utf-8')  # Encrypt the content before storing

            # Create a new Message object and save it to the database
            message = Message.objects.create(content=encrypted_content, sender=sender, payment=payment)

            # Serialize and return the response
            return Response({
                'message': 'Message received successfully',
                'content': content,  # Return original content
                'sender': sender,
                'payment': payment,
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# API view for getting all messages
class GetMessagesView(APIView):
    def get(self, request, *args, **kwargs):
        messages = Message.objects.all()  # Get all messages from the database
        
        # Decrypt the content of each message
        for message in messages:
            try:
                message.decrypted_content = f.decrypt(message.content.encode('utf-8')).decode('utf-8')
            except Exception as e:
                logger.error(f"Decryption error for message ID {message.id}: {e}")
                message.decrypted_content = "Decryption failed"

        # Serialize and return the decrypted messages
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


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
