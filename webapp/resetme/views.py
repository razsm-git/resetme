from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from .forms import UserForm
from re import search
from time import sleep

def index(request):
    #return HttpResponse("Hello, world. You're at the resetme index.")
    #return render(request, 'index.html')
    #username = request.POST.get('username')
    # if this is a POST request we need to process the form data
    print(f'This is request method {request.method}')
    if request.method == "POST":
        submitbutton= request.POST.get("submit")
        username = ''
        form= UserForm(request.POST or None)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            context= {'form': form, 'username': username, 'submitbutton': submitbutton}
            return redirect("success")
            #return HttpResponse(f"Hello, {username}. You're at the resetme success.")
    else:
        form= UserForm(request.GET)
        context= {'form': form}
        return render(request, 'index.html', context)
        #return HttpResponseRedirect("success/")


def success(request):
    #return HttpResponse("Hello, world. You're at the resetme success.")
    # print(request)
    # print(f"This is redirect {request.META.get('HTTP_REFERER')}")
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        return render(request, 'success.html')
    else:
        return HttpResponseForbidden("Forbidden")