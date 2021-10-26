from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.contrib.staticfiles.urls import staticfiles_urlpatterns,static
from django.urls import path
from django.conf.urls import url
from django.contrib.auth import views as auth_views


 
urlpatterns = [
     path('', views.Home, name='home'),
     path('Login/', views.Login, name='login'),
     path('Register/', views.Register, name='register'),
     path('dashboard/', views.Dashboard, name='dashboard'),
     path('about-us/', views.About, name='about'),
     path('invest/', views.Investments, name='invest'),
     path('contact/', views.contact, name='contact'),
     path('contact-send/', views.ContactUs, name='contacter'),
     path('Request-cash/', views.Funds, name='funds'),
     path('loadinvestment/', views.loadmessage, name='loadmsg'),
     path('activate/<uidb64>/<token>/', views.activate, name='activate'),
      path('resend/<username>/', views.resend, name='resend'),
      path('password_resett/', views.CustomPasswordResetView.as_view(), name='password_resett'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

      
     
    path('logout/', views.logout_request, name='logout'),
]


urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)