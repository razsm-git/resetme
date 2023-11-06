from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from .forms import UserForm, VerifyPhone
from re import search
from smsru.service import SmsRuApi
# For generate randoom sms code
from random import choice, shuffle
# For postgresql
import psycopg2
import ldap
from secret import admin_username, admin_password
from vars import ad_server, user_dn, base_dn, retrieve_attributes, samaccoutname, search_filter


def index(request):
    #return HttpResponse("Hello, world. You're at the resetme index.")
    #return render(request, 'index.html')
    submitbutton = request.POST.get("submit")
    username = ''
    form = UserForm(request.POST or None)
    if form.is_valid():
        username = form.cleaned_data.get("username")
        #check_ldap_user(username)
        #if else
        #запускаем проверку имени пользователя в ldap и получаем его данные
        context = {'form': form, 'submitbutton': submitbutton}
        return redirect("verify")
    else:
        context = {'form': form}
        return render(request, 'index.html', context)
    
def check_ldap_user(username):
    search_scope = ldap.SCOPE_SUBTREE
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
        cn = ldap_check_user[0][-1]['cn'][0].decode('UTF-8')
        mobile = ldap_check_user[0][-1]['mail'][0].decode('UTF-8')
        mail = ldap_check_user[0][-1]['mobile'][0].decode('UTF-8')
        givenName = ldap_check_user[0][-1]['givenName'][0].decode('UTF-8')
        distinguishedName = ldap_check_user[0][-1]['distinguishedName'][0].decode('UTF-8')
        print(cn, mobile, mail, givenName, distinguishedName)

    # Close connection
    def close_ldap_session():
        l.unbind_s()

    # Run script
    ldap_connect()
    check_user()
    close_ldap_session()
    #return
    # Дописать словарь возврата со статусом, для анализа в функции index()

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