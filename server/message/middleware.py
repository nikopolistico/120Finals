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
        # Intercept the request and decrypt the body if it's a POST request to '/api/send-message/'
        if request.method == "POST" and '/api/send-message/' in request.path:
            try:
                # Decode the incoming request body
                payload = json.loads(request.body.decode('utf-8'))
                message_base64 = payload.get('message')

                if not message_base64:
                    return JsonResponse({'error': 'No message provided'}, status=400)

                # Decode from base64
                message_encrypted = base64.b64decode(message_base64)

                # Decrypt the message
                message_bytes = self.fernet.decrypt(message_encrypted)

                # Decode the decrypted message back to JSON
                decrypted_message = message_bytes.decode('utf-8')
                payload = json.loads(decrypted_message)

                # Replace the request body with decrypted payload
                request._body = json.dumps(payload).encode('utf-8')
                request.META['CONTENT_LENGTH'] = str(len(request._body))

            except Exception as e:
                return JsonResponse({'error': f"Decryption error: {str(e)}"}, status=500)

        # Pass the request to the next middleware or view
        response = self.get_response(request)
        return response
