from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
#from django.forms import ModelForm
from .forms import UserForm, VerifyPhone, DomainForm, ChangePassword
#from resetme.models import domain
#from django.db import models
from re import search
#from smsru.service import SmsRuApi
# For generate randoom sms code
from random import choice, shuffle
# For postgresql
import psycopg2
import ldap
from secret import admin_username, admin_password
from vars import var_your_domain, var_volhovez_local, sms_login, sms_password, algoritm, coding, iter, dklen, urandom_bytes, conditions
import requests
#from django.core.exceptions import ValidationError
from re import findall
#from django.utils.translation import ugettext as _
from os import urandom
import hashlib
from resetme.models import user
from datetime import datetime, date


def index(request):
    #return HttpResponse("Hello, world. You're at the resetme index.")
    #return render(request, 'index.html')
    submitbutton = request.POST.get("submit")
    username = ''
    form = UserForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        context = {'form': form, 'submitbutton': submitbutton, 'username': username}
        request.session['data'] = {'username': username}
        return redirect("domain")
        #return render(request, 'domain_choice.html', context)
    else:
        context = {'form': form}
        return render(request, 'index.html', context)
    
def domain_choice(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        submitbutton = request.POST.get("submit")
        domain = ''
        form = DomainForm(request.POST or None)
        if form.is_valid():
            domain = form.cleaned_data.get("domain")
            username = request.session.get('data', None)['username']
            context = {'form': form, 'submitbutton': submitbutton}
            if domain == 'your_domain':
                check_username = check_ldap_user(username, var_your_domain)
            elif domain == 'your_domain':
                check_username = check_ldap_user(username, var_volhovez_local)
            #print(check_username)
            if check_username['status'] == 0:
            # User exist and ready for verify phone by sms code
                context = {'form': form, 'submitbutton': submitbutton}
                request.session['data'] = {'username': username, "mobile": check_username['mobile'], "distinguishedName": check_username['distinguishedName'], "givenName": check_username['givenName'], 'domain': domain}
                # Временно перенаправлю на ввод пароля
                #return redirect("verify")
                return redirect("password")
            elif check_username['status'] == 1:
                error_message = 'Такого пользователя не существует. Обратитесь в отдел ИТ.'
                context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message}
            elif check_username['status'] == 2:
                error_message = 'Для того, чтобы верифицировать Вас, нехватает данных или они не верны. Обратитесь в отдел ИТ.'
                context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message}
            return render(request, 'domain_choice.html', context)
        else:
            form = DomainForm()
            context = {'form': form}
            return render(request, 'domain_choice.html', context)
    else:
        return HttpResponseForbidden("Forbidden")
    
def check_ldap_user(username, domain):
    ad_server = domain['ad_server']
    search_scope = ldap.SCOPE_SUBTREE
    search_filter = f'(&(sAMAccountName={username})(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=* @example.ru)(mobile=8*))'
    def ldap_connect():
        try:
            # Force cert validation
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            # Declare global var l
            global l
            # LDAP connection initialization
            l = ldap.initialize(ad_server)
            l.set_option(ldap.OPT_REFERRALS, 0)
            # Set LDAP protocol version used
            l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            l.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            l.set_option(ldap.OPT_X_TLS_DEMAND, True)
            l.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            # Bind (as admin user)
            l.simple_bind_s(admin_username, admin_password)
            print("Connected!")
        except Exception as ex:
            print(ex)

    # Check user status in LDAP (enabled or disabled)
    def check_user():
        base_dn = domain['base_dn']
        retrieve_attributes = domain['retrieve_attributes']
        ldap_check_user = l.search_s(base_dn, search_scope, search_filter, retrieve_attributes)
        if ldap_check_user:
            # If user exists and enabled in LDAP
            status = 0
            try:
                mobile = ldap_check_user[0][-1]['mobile'][0].decode('UTF-8')
                print(mobile)
                givenName = ldap_check_user[0][-1]['givenName'][0].decode('UTF-8')
                print(givenName)
                distinguishedName = ldap_check_user[0][0]
                print(distinguishedName)
                result = {"mobile": mobile,"distinguishedName": distinguishedName, "givenName": givenName, 'status': status}
                return result
            except Exception as ex:
                status = 2
                result = {'status': status}
                return result
        else:
            # If user not exists or disabled in LDAP
            status = 1
            result = {'status': status}
            return result

    # Close connection
    def close_ldap_session():
        l.unbind_s()

    # Run script
    ldap_connect()
    res = check_user()
    close_ldap_session()
    return res
    

def generate_code():
    numbers = ['1','2','3','4','5','6','7','8','9']
    #Generate random code
    shuffle(numbers)
    random_code = ''.join([choice(numbers) for n in range(6)])
    with open('db.txt', 'w') as db:
        db.write(random_code)
    return random_code
    
def verify_phone(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        if request.method == 'POST':
            submitbutton = request.POST.get("submit")
            code = ''
            form = VerifyPhone(request.POST or None)
            if form.is_valid():
                code = form.cleaned_data.get("code")
                # with open('db.txt', 'r') as db:
                #     send_code = db.readlines()[-1].strip('\n')
                if int(send_code) == int(code):
                    context = {'form': form, 'submitbutton': submitbutton}
                    return redirect("password")
                else:
                    context = {'form': form, 'submitbutton': submitbutton, 'code_error': 'Вы ввели неверный код!'}
                    return render(request, 'verify_phone.html', context)
        elif request.method == 'GET':
            # Generate random code
            send_code = generate_code()
            print(f'Отправленный код: {send_code}')
            # Send code by sms
            mobile = request.session.get('data', None)['mobile']
            status_code_sms = send_code_by_sms(sms_login, sms_password, mobile, send_code)
            form = VerifyPhone()
            context = {'form': form}
            return render(request, 'verify_phone.html', context)
    else:
        return HttpResponseForbidden("Forbidden")

def send_code_by_sms(login, password, phone, code):
    req = requests.get(f"https://smsc.ru/sys/send.php?login={login}&psw={password}&phones={phone}&mes={code}")
    return req.status_code

def change_password(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        data = request.session.get('data', None)
        if request.method == 'POST':
            submitbutton = request.POST.get("submit")
            # password = ''
            # confirm_password = ''
            form = ChangePassword(request.POST or None)
            if form.is_valid():
                # password = form.cleaned_data.get("new_password")
                # confirm_password = form.cleaned_data.get("confirm_new_password")
                if form.cleaned_data.get("new_password") != form.cleaned_data.get("confirm_new_password"):
                    error_message = 'Введенные пароли не совпадают!'
                    context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message}
                    return render(request, 'change_password.html', context)
                else:
                    error_message_class = PasswordValidator()
                    error_message = error_message_class.validate(password=form.cleaned_data.get("new_password"), username=data['username'],domain=data['domain'], conditions=conditions, model_user=user)                    
                    if error_message:
                        context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message}
                        return render(request, 'change_password.html', context)
                    else:
                        hash = hash_salt(form.cleaned_data.get("new_password"))
                        user_data = user.objects.create(
                            username = data['username'],
                            first_name = data['givenName'],
                            phone = data['mobile'],
                            status = 'Password changed',
                            created_at = datetime.now(),
                            hash = hash['hash'],
                            salt = hash['salt'],
                            domain = data['domain'],
                        )
                        return redirect("success")
        elif request.method == 'GET':
            form = ChangePassword()
            context = {'form': form}
            return render(request, 'change_password.html', context)
    else:
        return HttpResponseForbidden("Forbidden")

def hash_salt(password):
    salt = urandom(urandom_bytes)
    hash = hashlib.pbkdf2_hmac(algoritm, password.encode(coding),salt, iter, dklen=dklen)
    return {'salt': salt,'hash': hash}

def hash_unsalt(password, hash, salt, algoritm, iter, dklen):
    new_hash = hashlib.pbkdf2_hmac(algoritm,password.encode(coding), bytes(salt), iter, dklen=dklen)
    if new_hash == bytes(hash):
        return {'err_code': 1, 'err_msg': "Пароль уже использовался Вами ранее. Введите другой пароль"}
    else:
        return {'err_code': 0}

class PasswordValidator(object):
    def validate(self, password, username, domain, conditions, model_user):
        if not findall(conditions['upper'], password):
            return "Пароль должен содержать заглавные латинские буквы."
        elif not findall(conditions['lower'], password):
            return "Пароль должен содержать строчные латинские буквы."
        elif not findall(conditions['number'], password):
            return "Пароль должен содержать цифры"
        elif len(password) < 8:
            return "Длина пароля должна быть больше либо равна 8 символам!"
        # Below requests to DB
        else:
            sl = conditions['history']
            today_date = date.today().isoformat()
            # queryset for chache
            model_user.objects.filter(username=username, domain=domain)
            # the same query
            history_of_change = model_user.objects.filter(username=username).filter(domain=domain).order_by('-created_at')[:sl]
            today_changed = model_user.objects.filter(username=username, domain=domain, created_at__contains=today_date)
            print("Это запрос today_changed.count:")
            if today_changed.count() >= conditions['change_per_day']:
                return "Замечена подозрительная активность с участием вашего аккаунта. обратитесь в отдел ИТ для изменения пароля."
            ###queryset = model_user.objects.filter(username=username).filter(domain=domain).filter(created_at__gte='2023-01-01').values()
            #queryset = model_user.objects.filter(username=username, domain=domain).values_list('hash')
            print(f"Это запрос history: {history_of_change}")
            for entry in history_of_change:
                print({'hash': entry.hash, 'salt': entry.salt})
                comparison = hash_unsalt(password, entry.hash, entry.salt, algoritm, iter, dklen)
                if comparison['err_code'] == 1:
                    return comparison['err_msg']
                

def success(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        result = request.session.get('data', None)
        return render(request, 'success.html', context=result)
    else:
        return HttpResponseForbidden("Forbidden")