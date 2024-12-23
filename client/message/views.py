from django.shortcuts import render
from django.http import JsonResponse
import requests
import json
from django.contrib import messages
from cryptography.fernet import Fernet
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required



def landing_page(request):
    return render(request, 'landing.html')

@login_required
@csrf_exempt
def send_message(request):
    api_url = 'http://127.0.0.1:8001/api/receive-message/'

    if request.method == "POST":
        try:
            # Get the base64-encoded encrypted message from the body of the request
            payload = json.loads(request.body)
            message_base64 = payload.get('message')

            if not message_base64:
                return JsonResponse({'error': 'Message is required.'}, status=400)

            # Send the encrypted message to another service via POST request
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

@login_required
@csrf_exempt
def receive_payment_confirmation(request):
    if request.method == 'POST':
        try:
            # Get the JSON data from the request body
            data = json.loads(request.body)
            content = data.get('content')  # Get 'content' from the JSON data
            
            if content:
                # Logic to process the received payment confirmation (e.g., store it in the database)
                # For now, we'll just return a success message
                return JsonResponse({
                    "success": True,
                    "message": "Payment confirmation received successfully."
                })
            else:
                return JsonResponse({
                    "success": False,
                    "message": "No content provided."
                }, status=400)
        
        except json.JSONDecodeError:
            return JsonResponse({
                "success": False,
                "message": "Invalid JSON format."
            }, status=400)

    # If not a POST request, return method not allowed
    return JsonResponse({
        "success": False,
        "message": "Invalid request method."
    }, status=405)



def login_view(request):
    if request.user.is_authenticated:
        # Redirect to the dashboard or any other page if the user is logged in
        return redirect('payment')  # Replace 'payment' with your desired page (e.g., 'dashboard')

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('payment')  # Replace with the home URL or any page after login
        else:
            return render(request, 'login.html', {'error': 'Invalid username or password'})
    
    return render(request, 'login.html')

@login_required
def logout_view(request):
    if request.method == 'POST':  # Ensure it only accepts POST
        logout(request)  # Log the user out
        return redirect('login')  # Redirect to the login page after logging out
    return redirect('login')  # 



def signup_view(request):
    if request.user.is_authenticated:
        # Redirect to the dashboard or any other page if the user is logged in
        return redirect('payment')  # Replace 'payment' with your desired page (e.g., 'dashboard')

    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        password_confirm = request.POST['password_confirm']

        # Check if passwords match
        if password != password_confirm:
            return render(request, 'registration.html', {'error': 'Passwords do not match.'})

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            return render(request, 'registration.html', {'error': 'Username already exists.'})

        if User.objects.filter(email=email).exists():
            return render(request, 'registration.html', {'error': 'Email already registered.'})

        # Create a new user
        user = User.objects.create_user(username=username,first_name=first_name,last_name = last_name, email=email, password=password)
        login(request, user)  # Log the user in after registration

        messages.success(request, 'Registration successful! You are now logged in.')
        
        return redirect('signup')  # Redirect to payment or home page

    return render(request, 'registration.html')


@login_required
def dashboard_view(request):
    # Assuming the logged-in user is available in the request object
    context = {
        'user_name': request.user.username  # You can use request.user.first_name or request.user.get_full_name() if needed
    }
    return render(request, 'payment.html', context)
