from django.contrib import admin
from django.urls import path, include
from registration.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('add_user/', add_user_api, name='add_user'),
    path('login/', login_user_api, name='login'),
    path('api/check-authenticated/', verify_token, name='check_authenticated'),
    path('activate/<str:activation_token>/', activate, name='activate'),
    path('signout/', signout, name='signout'),
    path('password_reset/', password_reset, name='password_reset'),
    path('reset_success/<str:token>/', reset_success, name='reset_success'),
    path('guitarists/', GuitaristListView, name='guitarist-list'),
    path('guitarists/<int:pk>/edit/', GuitaristEditView, name='guitarist_edit'),
    path('guitarists/create/', GuitaristPostView, name='guitarist-create'),
    path('upload/', FileUploadAPIView.as_view(), name='file-upload'),
    path('upload_file/', upload_file_to_s3, name='upload_file_to_s3'),
    path('list_audio/', list_audio, name='list_audio'),
    path('play_audio/<str:audio_key>/', play_audio, name='play_audio'),
]