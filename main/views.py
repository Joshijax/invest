from django.shortcuts import render
from django.shortcuts import render

from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth.models import User
from django.urls import reverse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
# from .forms import AgentUploadFileForm, AgentSignUpForm, ProfileUploadForm, ImageForm
import os
# from django.template import loader
# from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib import messages

from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from main.models import Invest, Message
from .token_generator import account_activation_token
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
            return redirect('main:dashboard')
        else:
           
            return f(request, *args, *kwargs)

    return wrap

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    # checking if the user exists, if the token is valid.
    if user is not None and account_activation_token.check_token(user, token):
        # if valid set active true
        user.is_active = True
        profile = user.profile # because of signal and one2one relation
        profile.email_confirm = True
        profile.save()
        # set signup_confirmation true

        user.save()
        
        

        messages.add_message(request, messages.SUCCESS, 'email authenticated')
        return redirect('main:login')
    else:
        messages.add_message(request, messages.WARNING, 'iNVALID LINK or EXPIRED')
        return redirect('/')

def resend(request, username):

    user = User.objects.get(username=username)
    try:
        current_site = get_current_site(request)
        email_subject = 'Activate Your Molite Account'
        message = render_to_string('activate_account.html', {
                'user': user.username,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.id)),
                'token': account_activation_token.make_token(user),
            })
        to_email = user.email
        email = EmailMessage(email_subject, message, to=[to_email])
        email.content_subtype = 'html'
        email.send()
        messages.add_message(request, messages.SUCCESS, 'Email has been sent, check your email')
    except:
        messages.add_message(request, messages.ERROR, 'Something Went wrong try again...')
        return redirect('main:login')
    
    print('pomit', User.objects.get(username=username).profile.email_confirm)
    
    return redirect('main:login')



def  Home(request):
    return render(request, 'home.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})

@is_logged_in
@csrf_exempt
def  Login(request):
    if request.method == 'POST':
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        print(username, password)
        
        if not User.objects.filter(username=username).exists():
            return JsonResponse({'message':'username Does not exist', 'message_type':'danger'})

        if not authenticate(username=username, password=password):
            return JsonResponse({'message':'password does not match', 'message_type':'warning'})

        if User.objects.get(username=username).profile.email_confirm is False:
            resend = reverse('main:resend', kwargs={'username':username})
            print(resend)
            print(User.objects.get(username=username).profile.email_confirm)
            return JsonResponse({'message': f'Email is not verified. click <a href="{resend}" style="color: blue;">here</a> to resend ', 'message_type':'danger'})

        user = authenticate(username=username, password=password)

        login(request, user)
        request.session['username'] = username
        # if request.user.profile.role ==  'Agent':
        #     return JsonResponse({'success':'success',
        #     'redirect': reverse('main:register'),})

        return JsonResponse({'message':'success', 'redirect': reverse('main:dashboard'), 'message_type':'success'})

        # load1 = request.POST.get('load1', None)
    return render(request, 'login.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})

@is_logged_in
@csrf_exempt
def Register(request):
    if request.method == 'POST':


        firstname = request.POST.get('name', None)
        lastname = request.POST.get('lastname', None)
        username = request.POST.get('username', None)
        emaill = request.POST.get('email', None)
        password1 = request.POST.get('password', None)
        password2 = request.POST.get('password2', None)
        phone = request.POST.get('phone', None)
        print(firstname, lastname, username, emaill, password1, password2, phone)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'message':'username already exists', 'message_type':'danger'})

        if User.objects.filter(email=emaill).exists():
            return JsonResponse({'message':'email already in use','message_type':'danger'})

        if len(password1) < 5:
            return JsonResponse({'message':'password should be greater than 5', 'message_type':'warning'})
        user = User.objects.create(
            first_name = firstname,
            last_name = lastname,
            username = username,
            email = emaill,
            password = password1,

        )

        current_site = get_current_site(request)
        email_subject = 'Activate Your Molite Account'
        message = render_to_string('activate_account.html', {
                'user': user.username,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.id)),
                'token': account_activation_token.make_token(user),
            })
        to_email = emaill
        email = EmailMessage(email_subject, message, to=[to_email])
        email.content_subtype = 'html'
        email.send()


        user =  User.objects.get(username=username,)
        profile = user.profile # because of signal and one2one relation
        profile.phone = phone
        profile.save()
        messages.add_message(request, messages.SUCCESS, 'Successfully created account, confirm email to login')

        return JsonResponse({'message':'Succesfully created your account', 'redirect': reverse('main:login'), 'message_type':'success'})
    return render(request, 'register.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})

@login_required(login_url='/Login')
def  Dashboard(request):
    invest = Invest.objects.all()
    user= request.user
    print(User._meta.get_fields(), user.profile.phone)
    return render(request, 'dashboard.html', {'media_url': settings.MEDIA_URL, 'invest': invest,})

def  About(request):
    return render(request, 'about.html', {'media_url': settings.MEDIA_URL, 'media_root': settings.MEDIA_ROOT,})

@login_required(login_url='/Login')
def  Investments(request):
    invest = Invest.objects.all()
    return render(request, 'invest.html', {'media_url': settings.MEDIA_URL, 'invest': invest,})

@login_required(login_url='/Login')
@csrf_exempt
def  loadmessage(request):
    current_site = get_current_site(request)
    emaill = request.POST.get('email', None)
    user = User.objects.get(email=emaill)
    print(emaill, user.username)
    email_subject = f'{user.username} Just made an investment'
    message = render_to_string('investmsg.html', {
            'user': user,
            'domain': current_site.domain,
        })
    to_email = 'Leookagbare@gmail.com'
    email = EmailMessage(email_subject, message, to=[to_email])
    email.content_subtype = 'html'
    email.send()

    msg = Message.objects.all()

    email_subject1 = f' Hello {user.username} Investment recieved'
    message1 = render_to_string('investmsg2.html', {
            'user': user,
            'msg': msg,
            'domain': current_site.domain,
        })
    to_email1 = emaill
    email = EmailMessage(email_subject1, message1, to=[to_email1])
    email.content_subtype = 'html'
    email.send()
    return render(request, 'includes/message.html', {'media_url': settings.MEDIA_URL,'message': msg})







def logout_request(request):

    logout(request)
    

    return redirect('main:login')
  