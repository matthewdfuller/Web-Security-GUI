from django.shortcuts import render, get_object_or_404

# Create your views here.
def home(request):
    return render(request, 'manage/manage_home.html')

def settings(request):
    return render(request, 'manage/manage_settings.html')

def help(request):
    return render(request, 'manage/manage_help.html')

def resources(request):
    return render(request, 'manage/manage_resources.html')