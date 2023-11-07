from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from django.forms import ModelForm
from .forms import UserForm, VerifyPhone, Domain
from resetme.models import domain
from re import search
from smsru.service import SmsRuApi
# For generate randoom sms code
from random import choice, shuffle
# For postgresql
import psycopg2
import ldap
from secret import admin_username, admin_password
from vars import ad_server, user_dn, base_dn, retrieve_attributes


def index(request):
    #return HttpResponse("Hello, world. You're at the resetme index.")
    #return render(request, 'index.html')
    submitbutton = request.POST.get("submit")
    username = ''
    form = UserForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        #check_username = check_ldap_user(username)
        context = {'form': form, 'submitbutton': submitbutton, 'username': username}
        domain_choise(request, username)
        return redirect("domain")
        #return render(request, 'domain_choise.html', context)
    #     if check_username['status'] == 0:
    #         # User exist and ready for verify phone by sms code
    #         context = {'form': form, 'submitbutton': submitbutton}
    #         return redirect("verify")
    else:
        context = {'form': form}
        return render(request, 'index.html', context)
    
def domain_choise(request):
    submitbutton = request.POST.get("submit")
    domain = ''
    class DomainForm(ModelForm):
        class Meta:
            model = domain
            fields = ["domain"]
    form = DomainForm(request.POST or None)
    if form.is_valid():
        domain = form.cleaned_data.get("domain")
        context = {'form': form, 'submitbutton': submitbutton,'domain': domain}
        return render(request, 'domain_choise.html', context)
    else:
        form = DomainForm()
        context = {'form': form}
        return render(request, 'domain_choise.html', context)
    
def check_ldap_user(username):
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
        ldap_check_user = l.search_s(base_dn, search_scope, search_filter, retrieve_attributes)
        if ldap_check_user:
            # If user exists and enabled in LDAP
            status = 0
            try:
                mobile = ldap_check_user[0][-1]['mail'][0].decode('UTF-8')
                mail = ldap_check_user[0][-1]['mobile'][0].decode('UTF-8')
                givenName = ldap_check_user[0][-1]['givenName'][0].decode('UTF-8')
                distinguishedName = ldap_check_user[0][0]
                result = {"mobile": mobile, "mail": mail, "distinguishedName": distinguishedName, "givenName": givenName, 'status': status}
                return result
            except Exception as ex:
                status = 2
                result = {'status': status}
                return result
        else:
            # If user not exists or disabled in LDAP
            status = 1

    # Close connection
    def close_ldap_session():
        l.unbind_s()

    # Run script
    ldap_connect()
    res = check_user()
    close_ldap_session()
    #return
    # Дописать словарь возврата со статусом, для анализа в функции index()
    return res
    

def generate_code():
    numbers = ['1','2','3','4','5','6','7','8','9']
    #Generate random code
    shuffle(numbers)
    random_code = ''.join([choice(numbers) for n in range(6)])
    with open('db.txt', 'w') as db:
        db.write(random_code)
    #return random_code
    
def verify_phone(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        if request.method == 'POST':
            submitbutton = request.POST.get("submit")
            code = ''
            form = VerifyPhone(request.POST or None)
            if form.is_valid():
                code = form.cleaned_data.get("code")
                with open('db.txt', 'r') as db:
                    send_code = db.readlines()[-1].strip('\n')
                if int(send_code) == int(code):
                    context = {'form': form, 'submitbutton': submitbutton}
                    return redirect("success")
                else:
                    context = {'form': form, 'submitbutton': submitbutton, 'code_error': 'Вы ввели неверный код!'}
                    return render(request, 'verify_phone.html', context)
        elif request.method == 'GET':
            # # Send code by sms
            generate_code()
            # print(f'Отправленный код: {send_code}')
            # print(type(int(send_code)))
            # api = SmsRuApi()
            # #Тут необходимо подставить данные из ldap и сгенерировать случайный код
            # result = api.send_one_sms("+79110400598", random_code)
            # print(result)
            form = VerifyPhone()
            context = {'form': form}
            return render(request, 'verify_phone.html', context)
    else:
        return HttpResponseForbidden("Forbidden")


def success(request):
    if search(r'http://127.0.0.1:8000/resetme/',request.META.get('HTTP_REFERER')):
        return render(request, 'success.html')
    else:
        return HttpResponseForbidden("Forbidden")