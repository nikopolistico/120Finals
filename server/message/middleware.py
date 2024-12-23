import base64
import json
from cryptography.fernet import Fernet
from django.http import JsonResponse
from django.conf import settings

class DecryptionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.fernet = Fernet(settings.ENCRYPT_KEY)

    def __call__(self, request):
        # Handle POST requests to /api/send-message/
        if request.method == "POST" and '/api/send-message/' in request.path:
            try:
                # Parse the request body as JSON
                payload = json.loads(request.body.decode('utf-8'))
                
                # Extract the encrypted message
                message_base64 = payload.get('message')
                if not message_base64:
                    return JsonResponse({'error': 'No message provided'}, status=400)

                # Decode the message from base64
                try:
                    encrypted_message = base64.b64decode(message_base64)
                except base64.binascii.Error:
                    return JsonResponse({'error': 'Invalid base64 encoding'}, status=400)

                # Decrypt the message using Fernet
                try:
                    decrypted_bytes = self.fernet.decrypt(encrypted_message)
                except Exception:
                    return JsonResponse({'error': 'Decryption failed'}, status=400)

                # Decode the decrypted bytes to JSON
                decrypted_payload = json.loads(decrypted_bytes.decode('utf-8'))

                # Replace the request body with the decrypted content
                request._body = json.dumps(decrypted_payload).encode('utf-8')
                request.META['CONTENT_LENGTH'] = str(len(request._body))

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON format'}, status=400)
            except Exception as e:
                return JsonResponse({'error': f'Decryption error: {str(e)}'}, status=500)

        # Handle GET requests to /api/get-messages/
        if request.method == "GET" and '/api/get-messages/' in request.path:
            try:
                # If you're returning encrypted data in the response, decrypt it here
                # Here, we assume the messages are already decrypted and just sent back to the view
                pass  # Add decryption logic here if necessary (usually not needed for GET requests)
            except Exception as e:
                return JsonResponse({'error': f'Decryption error: {str(e)}'}, status=500)

        # Pass the request to the next middleware or view
        return self.get_response(request)
