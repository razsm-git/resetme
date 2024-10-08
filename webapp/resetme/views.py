from django.shortcuts import render, redirect
from django.http import HttpResponseForbidden, HttpResponseServerError
from .forms import UserForm, VerifyPhone, DomainForm, ChangePassword
from re import search
# For generate randoom sms code
from random import choice, shuffle
import ldap
from secret import sms_login, sms_password
from vars import *
import requests
from re import findall
from os import urandom
# For hash and salt pass
import hashlib
from resetme.models import user, domain
from datetime import datetime, date
import redis


def index(request):
    # Redis connection
    r = redis.Redis(host=redis_host, port=redis_port, db=db)
    submitbutton = request.POST.get("submit")
    username = ''
    if not request.session._session_key:
        request.session.create()
    else:
        session_id = request.session._session_key
    session_id = request.session.session_key
    if request.method == 'GET':
        form = UserForm()
        context = {'form': form,'company_name': company_name, 'background_color_index': background_color_index, 'title_name': title_name}
        r.hset(session_id,'count_of_fails_form', 0)
        r.hset(session_id, 'created_at', datetime.now().strftime('%d.%m.%y %H:%M'))
        r.expire(session_id,redis_ttl)
        r.close()
        return render(request, 'index.html', context)
    elif request.method == 'POST':
        form = UserForm(request.POST or None)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            request.session['data'] = {'username': username}
            try:
                r.delete(session_id)
                r.close()
            except Exception as ex:
                pass
            return redirect("domain")
        else:
            r.hincrby(session_id, 'count_of_fails_form', 1)
            if int(r.hget(session_id, 'count_of_fails_form').decode()) < count_of_fails_form_threshold:
                context = {'form': form, 'company_name': company_name, 'background_color_index': background_color_index, 'title_name': title_name}
                r.close()
                return render(request, 'index.html', context)
            else:
                request.session.flush()
                r.delete(session_id)
                r.close()
                return HttpResponseForbidden()

    
def domain_choice(request):
    if search(site_url,request.META.get('HTTP_REFERER')):
        submitbutton = request.POST.get("submit")
        d = ''
        form = DomainForm(request.POST or None)
        if form.is_valid():
            d = form.cleaned_data.get("domain")
            username = request.session.get('data', None)['username']
            context = {'form': form, 'submitbutton': submitbutton, 'company_name': company_name, 'background_color_domain_choice': background_color_domain_choice}
            if d:
                domain_data = domain.objects.get(domain_name=d)
                check_ldap_user.ldap_connect(ad_server=domain_data.ad_server,admin_username=domain_data.admin_username,admin_password=domain_data.admin_password)
                check_username = check_ldap_user.check_user(username=username, search_filter=domain_data.search_filter, base_dn=domain_data.base_dn, retrieve_attributes=domain_data.retrieve_attributes.split(','))
                check_ldap_user.close_ldap_session()
            if check_username['status'] == 0:
            # User exist and ready for verify phone by sms code
                context = {'form': form, 'submitbutton': submitbutton, 'company_name': company_name, 'background_color_domain_choice': background_color_domain_choice}
                request.session['data'] = {'username': username, "mobile": check_username['mobile'], "distinguishedName": check_username['distinguishedName'], "givenName": check_username['givenName'], 'domain': d, 'redis_ttl_sms_code': redis_ttl_sms_code}
                return redirect("verify")
            elif check_username['status'] == 1:
                error_message = 'Такого пользователя не существует. Обратитесь в отдел ИТ.'
                context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message, 'company_name': company_name, 'background_color_domain_choice': background_color_domain_choice}
            elif check_username['status'] == 2:
                error_message = 'Для того, чтобы верифицировать Вас, нехватает данных или они не верны. Обратитесь в отдел ИТ.'
                context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message, 'company_name': company_name, 'background_color_domain_choice': background_color_domain_choice}
            return render(request, 'domain_choice.html', context)
        else:
            context = {'form': form, 'company_name': company_name, 'background_color_domain_choice': background_color_domain_choice}
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
    def check_user(username, search_filter, base_dn, retrieve_attributes):
        search_scope = ldap.SCOPE_SUBTREE
        try:
            ldap_check_user = l.search_s(base=base_dn, scope=search_scope, filterstr=search_filter.format(username), attrlist=retrieve_attributes)
        except Exception as ex:
            pass
        finally:
            if ldap_check_user:
                # If user exists and enabled in LDAP
                status = 0
                try:
                    mobile = ldap_check_user[0][-1]['mobile'][0].decode('UTF-8')
                    givenName = ldap_check_user[0][-1]['givenName'][0].decode('UTF-8')
                    distinguishedName = ldap_check_user[0][0]
                    result = {"mobile": mobile,"distinguishedName": distinguishedName, "givenName": givenName, 'status': status}
                    return result
                except Exception:
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
    if search(site_url,request.META.get('HTTP_REFERER')):
        r = redis.Redis(host=redis_host, port=redis_port, db=db)
        session_id = request.session._session_key
        if request.method == 'POST':
            if 'submit' in request.POST:
                submitbutton = request.POST.get("submit")
                code = ''
                form = VerifyPhone(request.POST or None)
                try:
                    send_code = r.hget(session_id, 'send_code').decode()
                except Exception:
                    send_code = False
                if form.is_valid():
                    code = form.cleaned_data.get("code")
                    if send_code and code and int(send_code) == int(code):
                        context = {'form': form, 'submitbutton': submitbutton, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                        r.delete(session_id)
                        r.close()
                        return redirect("password")
                    else:
                        r.hincrby(session_id, 'count_of_fails_code', 1)
                        if int(r.ttl(session_id)) == -1:
                            r.expire(session_id,redis_ttl_sms_code)
                        if int(r.hget(session_id, 'count_of_fails_code').decode()) < count_of_fails_code_threshold:
                            r.close()
                            context = {'form': form, 'submitbutton': submitbutton, 'error_message': 'Вы ввели неверный код!', 'redis_ttl_sms_code': redis_ttl_sms_code, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                            return render(request, 'verify_phone.html', context)
                        else:
                            request.session.flush()
                            r.delete(session_id)
                            r.close()
                            return HttpResponseForbidden()
                else:
                    r.hincrby(session_id, 'count_of_fails_code', 1)
                    if int(r.hget(session_id, 'count_of_fails_code').decode()) < count_of_fails_code_threshold:
                        context = {'form': form, 'submitbutton': submitbutton, 'redis_ttl_sms_code': redis_ttl_sms_code, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                        return render(request, 'verify_phone.html', context)
                    else:
                        request.session.flush()
                        r.delete(session_id)
                        r.close()
                        return HttpResponseForbidden()
            if 'retry_code' in request.POST:
                send = send_code_from_form(request, session_id, r=r)
                if send == 200:
                    form = VerifyPhone()
                    context = {'form': form, 'retry_code_message': 'Код отправлен повторно.', 'redis_ttl_sms_code': redis_ttl_sms_code, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                    return render(request, 'verify_phone.html', context)
                else:
                    form = VerifyPhone()
                    context = {'form': form, 'error_code_message': 'При отправке кода произошла ошибка. Попробуйте ещё раз', 'redis_ttl_sms_code': redis_ttl_sms_code, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                    return render(request, 'verify_phone.html', context)
        elif request.method == 'GET':
            # Check if code was sended
            try:
                code_in_db = int(r.hget(session_id, 'send_code').decode())
                r.close()
                code_in_db_status = 0
            except Exception:
                code_in_db_status = 1
            if code_in_db_status == 0:
                form = VerifyPhone()
                context = {'form': form, 'redis_ttl_sms_code': redis_ttl_sms_code, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                return render(request, 'verify_phone.html', context)
            else:
                send_status = send_code_from_form(request, session_id, r=r)
                form = VerifyPhone()
                context = {'form': form, 'redis_ttl_sms_code': redis_ttl_sms_code, 'company_name': company_name, 'background_color_verify_phone': background_color_verify_phone}
                return render(request, 'verify_phone.html', context)
    else:
        request.session.flush()
        return HttpResponseForbidden()
    
def send_code_from_form(request, session_id, r):
    # Generate random code
    send_code = generate_code()
    # Send code by sms
    mobile = request.session.get('data', None)['mobile']
    status_code_sms = send_code_by_sms(sms_login, sms_password, mobile, send_code)
    if status_code_sms == 200:
        r.hset(session_id,'send_code', send_code)
        r.hset(session_id,'count_of_fails_code', 0)
        r.hset(session_id,'status', status_code_sms)
        r.hset(session_id, 'created_at', datetime.now().strftime('%d.%m.%y %H:%M'))
        r.expire(session_id,redis_ttl_sms_code)
        r.close()
        return status_code_sms
    else:
        return status_code_sms

def send_code_by_sms(login, password, phone, code):
    try:
        req = requests.get(f"https://smsc.ru/sys/send.php?login={login}&psw={password}&phones={phone}&mes={code}")
        return req.status_code
    except Exception:
        return 1


def change_password(request):
    if search(site_url,request.META.get('HTTP_REFERER')):
        data = request.session.get('data', None)
        if request.method == 'POST':
            submitbutton = request.POST.get("submit")
            form = ChangePassword(request.POST or None)
            if form.is_valid():
                if form.cleaned_data.get("new_password") != form.cleaned_data.get("confirm_new_password"):
                    error_message = 'Введенные пароли не совпадают!'
                    context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message, 'company_name': company_name, 'password_len': conditions['len'], 'background_color_change_password': background_color_change_password}
                    return render(request, 'change_password.html', context)
                else:
                    error_message_class = PasswordValidator()
                    error_message = error_message_class.validate(password=form.cleaned_data.get("new_password"), username=data['username'],domain_name=data['domain'], conditions=conditions, model_user=user)                 
                    if error_message:
                        context = {'form': form, 'submitbutton': submitbutton, 'error_message': error_message, 'company_name': company_name, 'password_len': conditions['len'], 'background_color_change_password': background_color_change_password}
                        request.session.flush()
                        return render(request, 'change_password.html', context)
                    else:
                        try:
                            #Now, try perform the password update
                            domain_data = domain.objects.get(domain_name=data['domain'])
                            check_ldap_user.ldap_connect(ad_server=domain_data.ad_server,admin_username=domain_data.admin_username,admin_password=domain_data.admin_password)
                            new_pwd_utf16 = '"{0}"'.format(form.cleaned_data.get("new_password")).encode('utf-16-le')
                            mod_list = [(ldap.MOD_REPLACE, "unicodePwd", new_pwd_utf16),]
                            l.modify_s(request.session.get('data', None)['distinguishedName'], mod_list)
                            check_ldap_user.close_ldap_session()
                            hash = hash_salt(form.cleaned_data.get("new_password"))
                            user.objects.create(
                                username = data['username'],
                                first_name = data['givenName'],
                                phone = data['mobile'],
                                status = 'Password changed',
                                hash = hash['hash'],
                                salt = hash['salt'],
                                domain_id = domain_data.id,
                            )
                            return redirect("success")
                        except Exception as ex:
                            request.session.flush()
                            return HttpResponseServerError("Упс..Что-то пошло не так...Сообщите об этом в отдел ИТ")
        elif request.method == 'GET':
            form = ChangePassword()
            context = {'form': form, 'company_name': company_name, 'password_len': conditions['len'], 'background_color_change_password': background_color_change_password}
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
    def validate(self, password, username, domain_name, conditions, model_user):
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
            model_user.objects.filter(username=username, domain_id=domain.objects.get(domain_name=domain_name).id)
            # the same query
            history_of_change = model_user.objects.filter(username=username).filter(domain_id=domain.objects.get(domain_name=domain_name).id).order_by('-created_at')[:sl]
            on_delete_history = model_user.objects.filter(username=username).filter(domain_id=domain.objects.get(domain_name=domain_name).id).order_by('-created_at')[sl-1:].values_list("id", flat=True)
            today_changed = model_user.objects.filter(username=username, domain_id=domain.objects.get(domain_name=domain_name).id, created_at__contains=today_date)
            if today_changed.count() >= conditions['change_per_day']:
                return "Замечена подозрительная активность с участием вашего аккаунта. обратитесь в отдел ИТ для изменения пароля."
            for entry in history_of_change:
                try:
                    comparison = hash_unsalt(password, entry.hash, entry.salt, algoritm, iter, dklen)
                    if comparison['err_code'] == 1:
                        return comparison['err_msg']
                except Exception:
                    pass
            # try delete old entry in history
            try:
                model_user.objects.filter(id__in=list(on_delete_history)).delete()
            except Exception as ex:
                pass

def success(request):
    if search(site_url,request.META.get('HTTP_REFERER')):
        context = {'givenName': request.session.get('data', None)['givenName'], 'company_name': company_name, 'time_for_apply_password': dc_time_sync, 'background_color_success': background_color_success }
        request.session.flush()
        return render(request, 'success.html', context)
    else:
        request.session.flush()
        return HttpResponseForbidden()