from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import login
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib import messages
from .models import *
from .forms import *
import uuid
from django.shortcuts import  get_object_or_404
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from .mongobackend import MongoEngineBackend
from functools import wraps
from django.utils.crypto import get_random_string
from botocore.exceptions import NoCredentialsError
import boto3
from pydub import AudioSegment
from pydub.utils import mediainfo
import os
from django.conf import settings

def add_user(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        hashed_password = make_password(password)
        activation_token = get_random_string(length=32)
        
        if User.objects.filter(email=email).exists():
            return render(request, 'add_user.html', {'error_message': 'User with this email already exists'})
            
        user = User(email=email, password=hashed_password, activation_token=activation_token)
        user.save()

        activation_link = f"{settings.SITE_URL}/activate/{activation_token}/"

        # Send an email with the activation link
        subject = "Activate Your Account"
        message = f"Please click the following link to activate your account: {activation_link}"
        from_email = 'souravmohanty0077@gmail.com'
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        return redirect('login')  # Redirect to the login page
    else:
        return render(request, 'add_user.html')

def activate(request, activation_token):
    user = get_object_or_404(User, activation_token=activation_token)
    if not user.verified:
        user.verified = True
        user.save()
        return render(request, 'activate.html', {'user': user})
    else:
        return HttpResponse("Invalid Link. This link has already been used for activation.")
    
def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Call the authenticate method from your custom backend
        user = MongoEngineBackend().authenticate(request, email=email, password=password)

        if user is not None:
            request.session['user_email'] = user.email 
            return redirect('guitarist_list')  
        else:
            return HttpResponse("Invalid email or password")

    return render(request, 'login_user.html')    



def password_reset(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # Create a one-time use token and save it to the user's model attribute
            token = get_random_string(length=32)
            user.password_reset_token = token
            user.save()

            reset_link = f"{settings.SITE_URL}/reset_success/{token}/"
            subject = "Reset Your Password"
            message = f"Please click the following link to reset your password: {reset_link}"
            from_email = 'souravmohanty0077@gmail.com'
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            return render(request, 'password_reset_sent.html')
        except User.DoesNotExist:
            return render(request, 'password_reset.html', {'error_message': 'No user with this email exists.'})

    return render(request, 'password_reset.html')

def reset_success(request, token):
    try:
        user = User.objects.get(password_reset_token=token)
        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if password == confirm_password:
                # Set the new password for the user
                user.password = make_password(password)
                user.save()

                # Clear the password reset token after successful password reset
                user.password_reset_token = ''
                user.save()

                # Redirect the user to the login page or any other appropriate page
                return redirect('login')  # Replace 'login' with the name of your login URL pattern
            else:
                return render(request, 'reset_succes.html', {'error_message': 'Passwords do not match.'})

        return render(request, 'reset_success.html')

    except User.DoesNotExist:
        return render(request, 'password_reset.html', {'error_message': 'Invalid or expired reset token.'})
        
def signout(request):
    if 'user_email' in request.session:
        del request.session['user_email']
        return redirect('login') 
    else:
        return HttpResponse("User email not found in session")

def user_verified(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check if the user is logged in and verified
        if 'user_email' in request.session:
            user = User.objects.get(email=request.session['user_email'])
            if user.verified:
                return view_func(request, *args, **kwargs)
            else:
                # Redirect to login page with a message if not verified
                return redirect('login')  # Redirect to login page
        else:
            # Redirect to login page if user is not logged in
            return redirect('login')  # Redirect to login page

    return _wrapped_view

@user_verified
def dashboard(request):
    return render(request, 'dashboard.html')

@user_verified
def guitarist_list(request):
    guitarist = Guitarist.objects.all()
    return render(request, 'guitarist_list.html', {'guitarist': guitarist})

@user_verified
def add_or_edit_guitarist(request, pk=None):
    if pk is None:
        guitarist = Guitarist()
    else:
        guitarist = get_object_or_404(Guitarist, pk=pk)

    if request.method == 'POST':
        form = GuitaristForm(request.POST, instance=guitarist)
        if form.is_valid():
            form.save()
            return redirect('guitarist_list')
    else:
        form = GuitaristForm(instance=guitarist)

    return render(request, 'guitarist_form.html', {'form': form, 'Guitarist': guitarist})

@user_verified
def delete_guitarist(request, pk):
    guitarist = get_object_or_404(Guitarist, pk=pk)
    if request.method == 'POST':
        guitarist.delete()
        return redirect('guitarist_list')
    return render(request, 'guitarist_confirm_delete.html', {'guitarist': guitarist}) 
 
@user_verified
def ajax_customer_create(request):
    if request.method == 'POST':
        data = {
            'name': request.POST['name'],
            'email': request.POST['email'],
            'address': request.POST['address'],
            'phone_number': request.POST['phone_number']
        }
        customer = Customer(**data)
        customer.save()
        return JsonResponse({'message': 'Customer created successfully!'})
    else:
        return render(request, 'ajax_customer_create.html')

@user_verified
def ajax_customer_detail(request, id):
    customer = get_object_or_404(Customer, id=id)
    return render(request, 'ajax_customer_detail.html', {'customer': customer})

@user_verified
def ajax_customer_update(request, id):
    customer = get_object_or_404(Customer, id=id)
    if request.method == 'POST':
        customer.name = request.POST['name']
        customer.email = request.POST['email']
        customer.address = request.POST['address']
        customer.phone_number = request.POST['phone_number']
        customer.save()
        return JsonResponse({'message': 'Customer updated successfully!'})
    else:
        return render(request, 'ajax_customer_update.html', {'customer': customer})

@user_verified
def ajax_customer_delete(request, id):
    customer = get_object_or_404(Customer, id=id)
    if request.method == 'POST':
        customer.delete()
        return JsonResponse({'message': 'Customer deleted successfully!'})
    else:
        return render(request, 'ajax_customer_delete.html', {'customer': customer})

@user_verified
def upload_view(request):
    return render(request, 'upload.html')

@user_verified
def upload_file_to_s3(request):
    if request.method == 'POST' and request.FILES.get('audio_file'):
        audio_file = request.FILES['audio_file']
        
        if audio_file.size == 0:
            return JsonResponse({'error_message': 'Empty file provided'}, status=400)
        
        # Initialize S3 client
        s3 = boto3.client('s3',
                          aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)

        # Upload the file to S3
        try:
            s3.upload_fileobj(audio_file, settings.AWS_STORAGE_BUCKET_NAME, audio_file.name)
            return JsonResponse({'message': 'File uploaded successfully!'}, status=200)
        except Exception as e:
            return JsonResponse({'error_message': str(e)}, status=500)
    
    return JsonResponse({'error_message': 'Invalid request'}, status=400)

@user_verified
def view_bucket_contents(request):
    # Get list of objects in the S3 bucket
    s3 = boto3.resource('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    bucket = s3.Bucket(settings.AWS_STORAGE_BUCKET_NAME)
    bucket_contents = bucket.objects.all()

    return render(request, 'view_bucket_contents.html', {'bucket_contents': bucket_contents})

@user_verified
def delete_bucket_contents(request):
    if request.method == 'POST':
        selected_items = request.POST.getlist('selected_items')
        
        # Initialize S3 client
        s3 = boto3.resource('s3',
                            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
        bucket = s3.Bucket(settings.AWS_STORAGE_BUCKET_NAME)
        
        # Delete selected items from the bucket
        for item_key in selected_items:
            obj = bucket.Object(item_key)
            obj.delete()
        
        return JsonResponse({'message': 'Selected items deleted successfully!'}, status=200)
    return JsonResponse({'error_message': 'Invalid request'}, status=400)

@user_verified
def list_audio(request):
    s3 = boto3.resource('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    bucket = s3.Bucket(settings.AWS_STORAGE_BUCKET_NAME)
    
    mp3_objects = bucket.objects.all()  # Fetch all objects in the bucket
    
    audio_files = [obj.key for obj in mp3_objects if obj.key.lower().endswith('.mp3')]
    
    return render(request, 'list_audio.html', {'audio_files': audio_files})


@user_verified
def play_audio(request, audio_key):
    s3 = boto3.client('s3',
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    url = s3.generate_presigned_url('get_object', Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': audio_key})

    response = HttpResponse()
    response['Content-Type'] = 'audio/mpeg'
    response['Content-Disposition'] = 'inline;filename="{}"'.format(audio_key)
    response.write(s3.get_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=audio_key)['Body'].read())
    return response

def audio_player_view(request):
    return render(request, 'audio_templates/audio_player.html')