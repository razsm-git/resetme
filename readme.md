# Readme

Resetme - это web сервис, который позволяет пользователям самостоятельно "сбрасывать" пароли в AD, даже когда срок действия пароля уже истёк или пользователь вообще забыл свой пароль.

Сервис требует ввода "капчи", для защиты от ботов, а также проводит верификацию и подтверждение личности пользователя с посмощью отправки смс сообщений на мобильный телефон пользователя, который указан в атрибуте mobile пользователя, в AD.

**P.S. Для нормальной работы resetme, Вы должны предоставить учётную запись с правами на сброс паролей пользователей в AD(как правило, это привелегии администратора домена)**

## Установка
В качестве ос использован lxc контейнер с образом Debian 11 bullseye (5.15.83-1)
Django версии 4.2.6 (установлен с помощью pip, т.к. в репозитории debian версии сильно устарела)
### Зависимости
Для работы проекта, необходимы следующие пакеты, которые были установлены с помощью pip:
- django-simple-captcha 0.5.20
- django-crispy-forms 2.1
- crispy-bootstrap4 2023.1
- django_redis 4.12.1
- django-redis-cache-3.0.1 или django-redis-sessions-0.6.2 (если необходимо только хранение сессий пользователя в кэше redis)

А также пакеты, которые были установлены с помощью системного менеджера пакетов apt:
- gunicorn 20.1.0-1
- python3-psycopg2 2.8.6-2



В проекте есть файлы vars.py и secret.py, которые хранят в себе переменные и логины/пароли.
### secret.py
- secret_key_django - ключ django сервера, который перенесён из settings.py
Учётные данные администратора домена(в данном случае для двух доменов)
- your_domain_admin_username = 'логин(без указания домена)'
- your_domain_admin_password = 'пароль'
- your_domain_admin_username = 'логин(без указания домена)'
- your_domain_admin_password = 'пароль'

**P.S. На данный момент сервис не поддерживает увеличение/уменьшение кол-ва доменов путём простой правки конфигурационных файлов**

- resetme_db_host = 'ip адрес хоста БД, например, localhost'
- resetme_db_port = 'если порт стандартный, можно оставить пустым'
- resetme_db = 'имя БД'
- resetme_db_user = 'имя пользователя БД'
- resetme_db_pass = 'пароль пользователя БД'

Данные для подключения к сервису отправки смс сообщений. Resetme рассчитан на работу с провайдером smsc.ru средствами API через HTTPS GET запросы
- sms_login = 'логин'
- sms_password = 'пароль'

### vars.py
Как и было описано выше, на данный момент, сервис рассчитан на работу с двумя доменами AD. 
Переменная  'your_url' содержит полный url, по которому осуществляется переход на сайт. Она используется в коде, чтобы запретить прямой переход на страницы верификации, смены пароля и т.д. login_validator и sms_code_validator - это регулярные выражения для проверки введенных в соответсвующие формы данных. 
Переменные, для работы с доменами, содержаться в словарях var_volhovez_local и var_your_domain. На примере одного из них, опишу каждое свойство:
- ad_server: ip address или FQDN вашего контролера домена
- base_dn: OU, в котором расположены пользователи, которым будет доступна функция сброса пароля, через данный сервис
- retrieve_attributes: список с атрибутами мобильного телефона и имени пользователя в AD
- search_filter: LDAP фильтр, для поиска пользоваателей в каталоге. По умолчанию ищем только "включенных" пользователей, у которых указан e-mail и мобильный телефон, согласно регулярному выражению
- admin_username: импорт переменной из secret.py
- admin_password: импорт переменной из secret.py

var_volhovez_local = {'ad_server': "ldaps://dc.domain.test:636",
                   'base_dn': 'OU=Users,DC=domain,DC=test', 'retrieve_attributes': ["mobile", "givenName"], 'search_filter': '(&(sAMAccountName={})(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*@mail.ru)(mobile=+7*))', 'admin_username':  your_domain_admin_username, 'admin_password': your_domain_admin_password}

Чтобы указать кол-во неудачных попыток ввода имени пользователя/"капчи", после которых сессия пользователя будет "сброшена" средствами django, измените значения этой переменной. По умолчанию 3
- count_of_fails_form_threshold = 3
Чтобы указать кол-во неудачных попыток ввода смс кода, после которых сессия пользователя будет "сброшена" средствами django, измените значения этой переменной. По умолчанию 3
- count_of_fails_code_threshold = 3

В нижеуказанных пепременных значения для хэширования и соли введённых паролей пользователей. Это сделано для храненияи отслеживания "истории паролей". Если Вы не знаете, что менять, оставьте значения по умолчанию. 
urandom_bytes = 16
algoritm = 'sha256'
coding = 'utf-8'
iter = 100000
dklen = 128
**P.S. при изменении значений, необходимо вручную очистить таблицу "resetme_user" базы данных от всех значений, т.к. сервис не сможет проверить хэш.**

Следующая переменнная, это словарь, в котором указаны критерии сложности пароля. Они проверяются функцией re.findall. Их количество жёстко задано, поэтому нельзя увеличивать/уменьшать количество ключей в словаре.
- len: пароль должен быть не короче указанной длины
- upper: пароль должен включать заглавные буквы
- lower: пароль должен включать строчные буквы
- number: пароль должен включать wbahs
- history: указываем, какое кодичество записей будет хранится в БД, для обеспечения работы "истории паролей"
**Обратите внимание, что чем больше значение этой переменной, тем дольше будет ппроверять функция. Это скажется на времени ожидания web страницы пользователем**
- change_per_day: разрешенное количество измененний пароля для одного пользоваателя в сутки
conditions = {'len': 8, 'upper': '[A-Z]', 'lower': '[a-z]', 'number': '[0-9]', 'history': 10, 'change_per_day': 1}

Сервис Resetme использует redis, для хранения некоторых временных данных. Ниже приведены основные настройки.
- redis_host = 'localhost'
- redis_port = 6379
- db = 0

Уделить внимание необходимо следующим пепременным. 
- redis_ttl = это таймаут нахождения пользователя на одной странице. После истечения указанного значения, сессия пользователя будет "сброшена" средствами django
- redis_ttl_sms_code = это ввремя, в течении которого валиден смс код, который был отправлен пользователю
По умолчанию переменные имеют следующие значения:
redis_ttl = 600
redis_ttl_sms_code = 120




return code from function which check user in LDAP:
0 - user ok
1 - user not exists or disabled in LDAP
2 - user field are incorrect 




#Сообщения об ошибках для пользователя:
Замечена подозрительная активность с участием вашего аккаунта. обратитесь в отдел ИТ для изменения пароля - означает, что пользователь пытается сбросить пароль более одного раза в сутки

#Оставить для лога переменную status_code_sms или для БД

# Если подключаться к ldaps с самоподписным сертификатом, то необходимо в конфигурации ldap на клиенте прописать:
#/etc/ldap/ldap.conf
TLS_REQCERT never

Данные о сессиях пользоватлей хранятся в кэше redis, поэтому нет необходимости настраивать удаление этих данных из БД.
#при изменении статических файлов(css, js, img ect) необходимо выполнить команду "python3 manage.py  collectstatic" и перезапустить сервис nginx "systemctl restart nginx"