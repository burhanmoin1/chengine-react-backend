from django.contrib import admin
from django.urls import path, include
from registration.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', add_user, name='add_user'),
    path('login/', login_user, name='login'),
    path('activate/<str:activation_token>/', activate, name='activate'),
    path('dashboard/', dashboard, name='dashboard'),
    path('signout/', signout, name='signout'),
    path('password_reset/', password_reset, name='password_reset'),
    path('reset_success/<str:token>/', reset_success, name='reset_success'),
    path('guitarist_list/', guitarist_list, name='guitarist_list'),
    path('add_guitarist/', add_or_edit_guitarist, name='add_guitarist'),
    path('edit_guitarist/<str:pk>/', add_or_edit_guitarist, name='edit_guitarist'),
    path('delete_guitarist/<str:pk>/', delete_guitarist, name='delete_guitarist'), 
    path('upload/', upload_view, name='upload_view'),
    path('upload_file/', upload_file_to_s3, name='upload_file_to_s3'),
    path('view_bucket/', view_bucket_contents, name='view_bucket_contents'),
    path('delete_bucket_contents/', delete_bucket_contents, name='delete_bucket_contents'),
    path('play_audio/<str:audio_key>/', play_audio, name='play_audio'),
    path('list_audio/', list_audio, name='list_audio'),
]