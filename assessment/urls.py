"""
URL configuration for assessment project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
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
from django.urls import path
from app.views import UserRegister,get_put_delete,UserLogin,NoteListCreateView,NoteDetailView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',UserRegister.as_view(), name="user_register"),
    path('get_put_delete_user/',get_put_delete.as_view(), name="get_put_delete_user"),
    path('user_login/',UserLogin.as_view(), name="user_login"),
    path('notes/', NoteListCreateView.as_view(), name='note-list-create'),
    path('notes_get_put_delete_user/<uuid:note_id>/', NoteDetailView.as_view(), name='notes_get_put_delete_user'),
]
