from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from .forms import UserForm, VerifyPhone
from re import search

def index(request):
    #return HttpResponse("Hello, world. You're at the resetme index.")
    #return render(request, 'index.html')
    submitbutton = request.POST.get("submit")
    username = ''
    form = UserForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        context = {'form': form, 'username': username, 'submitbutton': submitbutton}
        return redirect("verify")
    else:
        context = {'form': form}
        return render(request, 'index.html', context)

    
def verify_phone(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        submitbutton = request.POST.get("submit")
        code = ''
        form = VerifyPhone(request.POST or None)
        if form.is_valid():
            code = form.cleaned_data.get("code")
            context = {'form': form, 'code': code, 'submitbutton': submitbutton}
            print(f"Ваш введенный код: {code}")
            return redirect("success")
        else:
            context = {'form': form}
            return render(request, 'verify_phone.html', context)
    else:
        return HttpResponseForbidden("Forbidden")


def success(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        return render(request, 'success.html')
    else:
        return HttpResponseForbidden("Forbidden")