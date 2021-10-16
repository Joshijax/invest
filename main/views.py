from django.shortcuts import render
from django.shortcuts import render

from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth.models import User
from django.http import JsonResponse
# from .forms import AgentUploadFileForm, AgentSignUpForm, ProfileUploadForm, ImageForm
import os
# from django.template import loader
# from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
# from PIL import Image
from functools import wraps



def wrappers(func, *args, **kwargs):
    def wrapped():
        return func(*args, **kwargs)

    return wrapped

def is_logged_in(f):
    @wraps(f)
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated == True:
            return redirect('index')
        else:
           
            return f(request, *args, *kwargs)

    return wrap

def  Home(request):
    return render(request, 'home.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})


def  Login(request):
    return render(request, 'login.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})


def Register(request):
    return render(request, 'register.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})
