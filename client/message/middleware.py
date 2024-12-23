import json
import base64
from cryptography.fernet import Fernet
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

class EncryptionMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        super().__init__(get_response)
        self.fernet = Fernet(settings.ENCRYPT_KEY)

    def process_request(self, request):
        # Apply encryption only for POST requests to the specific API endpoint
        if request.method == "POST" and '/api/send-message/' in request.path:
            try:
                # Decode the incoming JSON payload
                payload = json.loads(request.body.decode('utf-8'))
                content = payload.get('content')
                sender = payload.get('sender')
                payment = payload.get('payment')

                # Validate if necessary fields are present
                if not content or not sender:
                    return JsonResponse({'error': 'Content and sender are required fields.'}, status=400)

                # Encrypt the message
                message_bytes = json.dumps({
                    'content': content,
                    'sender': sender,
                    'payment': payment
                }).encode('utf-8')
                encrypted_message = self.fernet.encrypt(message_bytes)

                # Encode the encrypted message to base64
                encrypted_payload = json.dumps({
                    'message': base64.b64encode(encrypted_message).decode('utf-8')
                })

                # Replace the request body with the encrypted message
                request._body = encrypted_payload.encode('utf-8')

                # Update content length for the new body
                request.META['CONTENT_LENGTH'] = str(len(request._body))

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON format.'}, status=400)
            except Exception as e:
                return JsonResponse({'error': f"Encryption error: {str(e)}"}, status=500)

    def process_response(self, request, response):
        return response
