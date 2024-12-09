"""web_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from plaguards.views import index, tools, about, tutorial, search, file_upload, redirect_result
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
# from plaguards import views

urlpatterns = [
    path("index/", index, name="index"),
    path("tools/", tools, name="tools"),
    path("about/", about, name="about"),
    path("tutorial/", tutorial, name="tutorial"),
    path("search/", search, name="search"),
    path("file_upload/", file_upload, name="file_upload"),
    path("", index, name="index"),
    path('redirect_result/', redirect_result, name="redirect_result"),
    # path('reports/', views.reports_view, name='reports'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
