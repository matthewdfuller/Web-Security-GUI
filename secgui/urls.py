from django.conf.urls import patterns, include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = patterns('',
    url(r'', include('manage.urls')),
    url(r'', include('quickscan.urls')),
    url(r'', include('scanner.urls')),
)

# Remove in production
urlpatterns += staticfiles_urlpatterns()