from django.shortcuts import render, redirect
from django.http import HttpResponseForbidden, HttpResponseServerError
from .forms import UserForm, VerifyPhone, DomainForm, ChangePassword
from re import search
# For generate randoom sms code
from random import choice, shuffle
import ldap
from secret import admin_username, admin_password, sms_login, sms_password
from vars import *
import requests
from re import findall
from os import urandom
# For hash and salt pass
import hashlib
from resetme.models import user, sms_code, bruteforce
from datetime import datetime, date


def index(request):
    submitbutton = request.POST.get("submit")
    username = ''
    if not request.session._session_key:
        request.session.create()
    else:
        session_id = request.session._session_key
    session_id = request.session.session_key
    if request.method == 'GET':
        form = UserForm()
        context = {'form': form}
        brute_force, created  = bruteforce.objects.update_or_create(
                session_id = session_id,
                count_of_fails_form = 0,
                defaults={'created_at': datetime.now()}
            )
        return render(request, 'index.html', context)
    elif request.method == 'POST':
        form = UserForm(request.POST or None)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            request.session['data'] = {'username': username}
            return redirect("domain")
        else:
            update_count_of_fails_form = {'count_of_fails_form': list(bruteforce.objects.filter(session_id=session_id).values_list
            ('count_of_fails_form', flat=True))[0] + 1}
            update_brute_force, update_created  = bruteforce.objects.update_or_create(
                session_id = session_id,
                defaults=update_count_of_fails_form
            )
            if update_count_of_fails_form['count_of_fails_form'] < count_of_fails_form_threshold:
                context = {'form': form}
                return render(request, 'index.html', context)
            else:
                request.session.flush()
                bruteforce.objects.filter(session_id=session_id).delete()
                return HttpResponseForbidden()
    
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
                check_ldap_user.ldap_connect(ad_server=var_your_domain['ad_server'],admin_username=admin_username,admin_password=admin_password)
                check_username = check_ldap_user.check_user(username=username, domain=var_your_domain)
                check_ldap_user.close_ldap_session()
            elif domain == 'your_domain':
                check_username = check_ldap_user(username, var_volhovez_local)
            if check_username['status'] == 0:
            # User exist and ready for verify phone by sms code
                context = {'form': form, 'submitbutton': submitbutton}
                request.session['data'] = {'username': username, "mobile": check_username['mobile'], "distinguishedName": check_username['distinguishedName'], "givenName": check_username['givenName'], 'domain': domain}
                return redirect("verify")
            elif check_username['status'] == 1:
                error_message = 'Такого пользователя не существует. Обратитесь в отдел ИТ.'
                context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message}
            elif check_username['status'] == 2:
                error_message = 'Для того, чтобы верифицировать Вас, нехватает данных или они не верны. Обратитесь в отдел ИТ.'
                context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message}
            return render(request, 'domain_choice.html', context)
        else:
            context = {'form': form}
            return render(request, 'domain_choice.html', context)
    else:
        request.session.flush()
        return HttpResponseForbidden()
    
class check_ldap_user(object):
    def ldap_connect(ad_server, admin_username, admin_password):
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
        except Exception as ex:
            pass

    # Check user status in LDAP (enabled or disabled)
    def check_user(username, domain):
        search_scope = ldap.SCOPE_SUBTREE
        search_filter = f'(&(sAMAccountName={username})(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=* @example.ru)(mobile=8*))'
        base_dn = domain['base_dn']
        retrieve_attributes = domain['retrieve_attributes']
        ldap_check_user = l.search_s(base_dn, search_scope, search_filter, retrieve_attributes)
        if ldap_check_user:
            # If user exists and enabled in LDAP
            status = 0
            try:
                mobile = ldap_check_user[0][-1]['mobile'][0].decode('UTF-8')
                givenName = ldap_check_user[0][-1]['givenName'][0].decode('UTF-8')
                distinguishedName = ldap_check_user[0][0]
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


def generate_code():
    numbers = ['1','2','3','4','5','6','7','8','9']
    #Generate random code
    shuffle(numbers)
    random_code = ''.join([choice(numbers) for n in range(6)])
    return random_code
    
def verify_phone(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        session_id = request.session._session_key
        if request.method == 'POST':
            if 'submit' in request.POST:
                submitbutton = request.POST.get("submit")
                code = ''
                form = VerifyPhone(request.POST or None)
                send_code = list(sms_code.objects.filter(session_id=session_id).values_list('send_code', flat=True))[0]
                if form.is_valid():
                    code = form.cleaned_data.get("code")
                    if int(send_code) == int(code):
                        context = {'form': form, 'submitbutton': submitbutton}
                        sms_code.objects.filter(session_id=session_id).delete()
                        return redirect("password")
                    else:
                        count_of_fails_code = {'count_of_fails_code': list(sms_code.objects.filter(session_id=session_id).values_list('count_of_fails_code', flat=True))[0] + 1}
                        update_count_of_fails_code, created = sms_code.objects.update_or_create(
                            session_id=session_id, 
                            send_code=send_code, 
                            defaults=count_of_fails_code
                        )
                        if count_of_fails_code['count_of_fails_code'] < count_of_fails_code_threshold:
                            context = {'form': form, 'submitbutton': submitbutton, 'error_message': 'Вы ввели неверный код!'}
                            return render(request, 'verify_phone.html', context)
                        else:
                            request.session.flush()
                            sms_code.objects.filter(session_id=session_id).delete()
                            return HttpResponseForbidden()
                else:
                    context = {'form': form}
                    return render(request, 'verify_phone.html', context)
            if 'retry_code' in request.POST:
                print('Кнопка Отправить код повторно - нажата.')
                send_code_from_form(request, session_id)
                form = VerifyPhone()
                context = {'form': form}
                return render(request, 'verify_phone.html', context)
        elif request.method == 'GET':
            # Check if code was sended
            try:
                code_in_db = list(sms_code.objects.filter(session_id=session_id).values_list('send_code', flat=True))[0]
                code_in_db_status = 0
            except Exception:
                code_in_db_status = 1
            if code_in_db_status == 0:
                form = VerifyPhone()
                context = {'form': form}
                return render(request, 'verify_phone.html', context)
            else:
                send_code_from_form(request, session_id)
                form = VerifyPhone()
                context = {'form': form}
                return render(request, 'verify_phone.html', context)
    else:
        request.session.flush()
        return HttpResponseForbidden()
    
def send_code_from_form(request, session_id):
    # Generate random code
    send_code = generate_code()
    print(f'Отправленный код: {send_code}')
    # Send code by sms
    mobile = request.session.get('data', None)['mobile']
    status_code_sms = send_code_by_sms(sms_login, sms_password, mobile, send_code)
    sms_data = sms_code.objects.update_or_create(
        session_id = session_id,
        #created_at = datetime.now(),
        status = status_code_sms,
        count_of_fails_code = 0,
        defaults={'send_code': send_code},
    )

def send_code_by_sms(login, password, phone, code):
    req = requests.get(f"https://smsc.ru/sys/send.php?login={login}&psw={password}&phones={phone}&mes={code}")
    return req.status_code

def change_password(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        data = request.session.get('data', None)
        if request.method == 'POST':
            submitbutton = request.POST.get("submit")
            form = ChangePassword(request.POST or None)
            if form.is_valid():
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
                        try:
                            hash = hash_salt(form.cleaned_data.get("new_password"))
                            user_data = user.objects.create(
                                username = data['username'],
                                first_name = data['givenName'],
                                phone = data['mobile'],
                                status = 'Password changed',
                                hash = hash['hash'],
                                salt = hash['salt'],
                                domain = data['domain'],
                            )
                            #Now, try perform the password update
                            check_ldap_user.ldap_connect(ad_server=var_your_domain['ad_server'],admin_username=admin_username,admin_password=admin_password)
                            new_pwd_utf16 = '"{0}"'.format(form.cleaned_data.get("new_password")).encode('utf-16-le')
                            mod_list = [(ldap.MOD_REPLACE, "unicodePwd", new_pwd_utf16),]
                            l.modify_s(request.session.get('data', None)['distinguishedName'], mod_list)
                            check_ldap_user.close_ldap_session()
                            return redirect("success")
                        except Exception as ex:
                            request.session.flush()
                            return HttpResponseServerError("Упс..Что-то пошло не так...")
        elif request.method == 'GET':
            form = ChangePassword()
            context = {'form': form}
            return render(request, 'change_password.html', context)
    else:
        request.session.flush()
        return HttpResponseForbidden()

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
            return "Пароль должен содержать заглавные латинские буквы!"
        elif not findall(conditions['lower'], password):
            return "Пароль должен содержать строчные латинские буквы!"
        elif not findall(conditions['number'], password):
            return "Пароль должен содержать цифры!"
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
            on_delete_history = model_user.objects.filter(username=username).filter(domain=domain).order_by('-created_at')[sl-1:].values_list("id", flat=True)
            today_changed = model_user.objects.filter(username=username, domain=domain, created_at__contains=today_date)
            print("Это запрос today_changed.count:")
            if today_changed.count() >= conditions['change_per_day']:
                return "Замечена подозрительная активность с участием вашего аккаунта. обратитесь в отдел ИТ для изменения пароля."
            ###queryset = model_user.objects.filter(username=username).filter(domain=domain).filter(created_at__gte='2023-01-01').values()
            #queryset = model_user.objects.filter(username=username, domain=domain).values_list('hash')
            print(f"Это запрос history: {history_of_change}")
            for entry in history_of_change:
                #print({'hash': entry.hash, 'salt': entry.salt})
                comparison = hash_unsalt(password, entry.hash, entry.salt, algoritm, iter, dklen)
                if comparison['err_code'] == 1:
                    return comparison['err_msg']
            # try delete old entry in history
            try:
                model_user.objects.filter(id__in=list(on_delete_history)).delete()
            except Exception as ex:
                pass

def success(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        context = {'givenName': request.session.get('data', None)['givenName']}
        request.session.flush()
        return render(request, 'success.html', context)
    else:
        request.session.flush()
        return HttpResponseForbidden()