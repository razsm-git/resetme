from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from .forms import UserForm, VerifyPhone
from re import search
from smsru.service import SmsRuApi
from random import choice, shuffle, randint

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
        # Send code by sms
        numbers = ['1','2','3','4','5','6','7','8','9']
        #Generate random code
        shuffle(numbers)
        #random_code = ''.join([choice(numbers) for n in range(6)])
        random_code = randint(100000, 999999)
        print(f'Отправленный код: {random_code}')
        print(type(int(random_code)))
        # api = SmsRuApi()
        # #Тут необходимо подставить данные из ldap и сгенерировать случайный код
        # result = api.send_one_sms("+79110400598", random_code)
        # print(result)
        submitbutton = request.POST.get("submit")
        code = ''
        form = VerifyPhone(request.POST or None)
        if form.is_valid():
            code = form.cleaned_data.get("code")
            print(f"Ваш введенный код: {code}")
            print(type(int(code)))
            print(f'Отправленный код: {random_code}')
            print(type(int(random_code)))
            if int(random_code) == int(code):
                context = {'form': form, 'submitbutton': submitbutton}
                return redirect("success")
            else:
                context = {'form': form, 'submitbutton': submitbutton, 'code_error': 'Вы ввели неверный код!'}
                return render(request, 'verify_phone.html', context)
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