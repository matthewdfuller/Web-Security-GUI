from django.conf.urls import patterns, url

from manage import views

urlpatterns = patterns('',
    url(r'^help/$', views.help, name='help'),
    url(r'^resources/$', views.resources, name='resources'),
)