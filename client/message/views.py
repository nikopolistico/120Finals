from django.shortcuts import render
from django.http import JsonResponse
import requests
import json
import base64
from cryptography.fernet import Fernet
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

f = Fernet(settings.ENCRYPT_KEY)

@csrf_exempt
def send_message(request):
    api_url = 'http://127.0.0.1:8002/api/receive-message/'  

    if request.method == "POST":
        try:
            # Get JSON data from the body of the request
            payload = json.loads(request.body)  # Decode and load the JSON payload
            content = payload.get('content')
            sender = payload.get('sender')
            payment = payload.get('payment')

            if not content or not sender:
                return JsonResponse({'error': 'Content and sender are required fields.'}, status=400)

            # Encrypt the content and sender data
            message_bytes = json.dumps({'content': content, 'sender': sender, 'payment': payment}).encode('utf-8')
            message_encrypted = f.encrypt(message_bytes)

            # Encode the encrypted message to base64 to safely transmit over HTTP
            message_base64 = base64.b64encode(message_encrypted).decode('utf-8')

            # Send the encrypted base64-encoded data to another service via POST request
            response = requests.post(api_url, data={'message': message_base64}, headers={'Content-Type': 'application/x-www-form-urlencoded'})

            if response.status_code == 201:
                return JsonResponse({
                    'message': 'Message sent successfully!',
                    'payload': payload
                }, status=201)
            else:
                return JsonResponse({'error': 'Failed to send message'}, status=response.status_code)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format.'}, status=400)
        
        except requests.exceptions.RequestException as e:
            return JsonResponse({'error': str(e)}, status=500)

    # For other methods, return method not allowed
    return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)

def payment_view(request):
    return render(request, 'payment.html')
