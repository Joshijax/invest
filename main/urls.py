from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.contrib.staticfiles.urls import staticfiles_urlpatterns,static
from django.urls import path


 
urlpatterns = [
     path('', views.Home, name='home'),
     path('Login/', views.Login, name='login'),
     path('Register/', views.Register, name='register'),
     path('dashboard/', views.Dashboard, name='dashboard'),
     path('about-us/', views.About, name='about'),
     path('invest/', views.Investments, name='invest'),
     path('loadinvestment/', views.loadmessage, name='loadmsg'),
     path('activate/<uidb64>/<token>/', views.activate, name='activate'),
     
    path('logout/', views.logout_request, name='logout'),
]


urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)