from django.shortcuts import render, redirect
from django.http import HttpResponseNotFound, HttpResponse, JsonResponse, HttpResponseBadRequest
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import login
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib import messages
from .models import *
from mutagen.mp3 import MP3
import uuid
import json 
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.permissions import AllowAny
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
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from pydub.utils import mediainfo
from django.core.serializers import serialize
import os
from django.conf import settings
import logging
from botocore.exceptions import ClientError
from django.views.decorators.csrf import csrf_exempt
import jwt
from bson import ObjectId  # Import ObjectId from bson library
from django.views import View
from .serializers import GuitaristForm


@api_view(['POST'])
def add_user_api(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        hashed_password = make_password(password)
        activation_token = get_random_string(length=32)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User(email=email, password=hashed_password, activation_token=activation_token)
        user.save()

        activation_link = f"/activate/{activation_token}/"

        # Send an email with the activation link
        subject = "Activate Your Account"
        message = f"Please click the following link to activate your account: {activation_link}"
        from_email = 'souravmohanty0077@gmail.com'
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
    else:
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

def activate(request, activation_token):
    user = get_object_or_404(User, activation_token=activation_token)
    if not user.verified:
        user.verified = True
        user.save()
        return render(request, 'activate.html', {'user': user})
    else:
        return HttpResponse("Invalid Link. This link has already been used for activation.")
    

@csrf_exempt
@api_view(['POST'])
def login_user_api(request):
    if request.method == 'POST':
        data = request.data  # Assuming the data is sent in JSON format
        email = data.get('email')
        password = data.get('password')
        session_token = data.get('session_token')
        # Call the authenticate method from your custom backend
        user = MongoEngineBackend().authenticate(request, email=email, password=password)

        if user is not None:

            login(request, user)
            # Save user email in session
            request.session['user_email'] = user.email
            user.session_token = session_token
            user.save()

            # Return user email and the generated token upon successful login
            return JsonResponse({'message': 'Login successful', 'user_email': request.session.get('user_email')})
        else:
            return JsonResponse({'error': 'Invalid email or password'}, status=400)

    return JsonResponse({'error': 'Method Not Allowed'}, status=405)


@csrf_exempt
@api_view(['POST'])
def verify_token(request):
    if request.method == 'POST':
        data = request.data  # Assuming the data is sent in JSON format
        session_token = data.get('session_token')  # Get the session token from the request data

        try:
            User.objects.get(session_token=session_token)

            # Token matches, return success response
            return JsonResponse({'message': 'Token verification successful'})
        except User.DoesNotExist:
            # Token doesn't match or doesn't exist in the user model
            return JsonResponse({'error': 'Invalid token'}, status=400)

    return JsonResponse({'error': 'Method Not Allowed'}, status=405)

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
        

@api_view(['POST'])  # Adjust the method as needed (POST, GET, etc.)
def signout(request):
    if 'user_email' in request.session:
        del request.session['user_email']
        return redirect('login')  # Redirect after deleting the session data
    else:
        return JsonResponse({"error": "User email not found in session"}, status=400)

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

from rest_framework import serializers
from .models import Guitarist
from django.forms.models import model_to_dict

def GuitaristListView(request):
    if request.method == 'GET':
        guitarists = Guitarist.objects.all()
        serialized_data = [model_to_dict(guitarist) for guitarist in guitarists]
        return JsonResponse(serialized_data, safe=False)
    
@csrf_exempt
def GuitaristPostView(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        form = GuitaristForm(data)
        if form.is_valid():
            new_guitarist = form.save(commit=False)
            new_guitarist.save()
            return JsonResponse({'message': 'Guitarist created successfully'}, status=201)
        else:
            return JsonResponse({'errors': form.errors}, status=400)
    else:
        return JsonResponse({'message': 'Only POST requests are allowed'}, status=405)
    

@csrf_exempt
def GuitaristEditView(request, pk):
    guitarist = get_object_or_404(Guitarist, pk=pk)
    
    if request.method == 'PUT' or request.method == 'PATCH':
        data = json.loads(request.body)
        form = GuitaristForm(data, instance=guitarist)
        
        if form.is_valid():
            edited_guitarist = form.save()
            serialized_data = model_to_dict(edited_guitarist)  # Serialize the updated guitarist
            return JsonResponse({'message': 'Guitarist updated successfully', 'data': serialized_data}, status=200)
        else:
            return JsonResponse({'errors': form.errors}, status=400)
    else:
        return JsonResponse({'message': 'Only PUT or PATCH requests are allowed'}, status=405)

MAX_ALLOWED_LENGTH_SECONDS = 500  # 2 minutes in seconds
MAX_ALLOWED_FILE_SIZE = 8.5 * 1024 * 1024  # 0.5 MB in bytes

def upload_file_to_s3(request):
    if request.method == 'POST' and request.FILES.get('audio_file'):
        audio_file = request.FILES['audio_file']

        if audio_file.size == 0:
            return JsonResponse({'error_message': 'Empty file provided'}, status=400)
        
        # Check the length of the audio file
        try:
            audio = MP3(audio_file)
            audio_length_seconds = audio.info.length
            
            if audio_length_seconds > MAX_ALLOWED_LENGTH_SECONDS:
                return JsonResponse({'error_message': 'Audio file too big (over 2 minutes)'}, status=400)
            
            # Get file size
            file_size = audio_file.size
            
            # Compress audio if the file size exceeds the limit
            if file_size > MAX_ALLOWED_FILE_SIZE:
                audio = AudioSegment.from_file(audio_file)
                compressed_audio = audio.export(format="mp3", bitrate="64k")  # Adjust the bitrate as needed
                audio_file = compressed_audio
            
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
        
        except Exception as e:
            return JsonResponse({'error_message': f'Error checking audio file: {e}'}, status=400)

    return JsonResponse({'error_message': 'Invalid request'}, status=400)

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


def list_audio(request):
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )
        response = s3.list_objects_v2(
            Bucket=settings.AWS_STORAGE_BUCKET_NAME
        )
        
        audio_files = []
        if 'Contents' in response:
            for obj in response['Contents']:
                if obj['Key'].lower().endswith('.mp3'):
                    audio_files.append(obj['Key'])

        return JsonResponse({'audio_files': audio_files, 'bucket_name': settings.AWS_STORAGE_BUCKET_NAME})
    except Exception as e:
        return JsonResponse({'error_message': str(e)}, status=500)
    

from rest_framework import serializers

class AudioFileSerializer(serializers.Serializer):
    audio_file = serializers.FileField()

class FileUploadAPIView(APIView):
    def get(self, request):
        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )
        
        try:
            # Retrieve a list of objects (files) in the bucket
            objects = s3.list_objects_v2(Bucket=settings.AWS_STORAGE_BUCKET_NAME)
            files = [obj['Key'] for obj in objects.get('Contents', [])]

        
            return Response({'files': files,}, status=status.HTTP_200_OK)
        except ClientError as e:
            return Response({'error_message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request):
        file_name = request.data.get('file_name')

        if not file_name:
            return Response({'error_message': 'File name is required'}, status=status.HTTP_400_BAD_REQUEST)

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )

        try:
            s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=file_name)
            return Response({'message': f'File {file_name} deleted successfully!'}, status=status.HTTP_200_OK)
        except ClientError as e:
            return Response({'error_message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'error_message': 'An error occurred while deleting the file'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def post(self, request):
        serializer = AudioFileSerializer(data=request.data)
        if serializer.is_valid():
            audio_file = serializer.validated_data['audio_file']
            if audio_file.size == 0:
                return Response({'error_message': 'Empty file provided'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                audio = MP3(audio_file)
                audio_length_seconds = audio.info.length
                
                if audio_length_seconds > MAX_ALLOWED_LENGTH_SECONDS:
                    return Response({'error_message': 'Audio file too big (over 2 minutes)'}, status=status.HTTP_400_BAD_REQUEST)
                
                file_size = audio_file.size
                
                if file_size > MAX_ALLOWED_FILE_SIZE:
                    audio = AudioSegment.from_file(audio_file)
                    compressed_audio = audio.export(format="mp3", bitrate="64k")  # Adjust the bitrate as needed
                    audio_file = compressed_audio
                    
                s3 = boto3.client('s3',
                                  aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                                  aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
                
                try:
                    s3.upload_fileobj(audio_file, settings.AWS_STORAGE_BUCKET_NAME, audio_file.name)
                    return Response({'message': 'File uploaded successfully!'}, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({'error_message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            except Exception as e:
                return Response({'error_message': f'Error checking audio file: {e}'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'error_message': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)