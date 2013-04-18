from django.conf.urls import patterns, url

from quickscan import views

urlpatterns = patterns('',
    url(r'^$', views.home, name='home'),
    url(r'^quickscan/$', views.home, name='home'),
    #Match the uuid format of quick scans
    url(r'^quickscan/(?P<scan_uuid>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})/$', views.results, name='results'),
)