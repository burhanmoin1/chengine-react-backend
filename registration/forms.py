from django_mongoengine import forms
from .models import *
from django.forms import ModelForm

class GuitaristForm(forms.DocumentForm):
    class Meta:
        document = Guitarist
        fields = '__all__' 
