Hi everyone. This is my project for self-service AD ​​password reset

return code from function which check user in LDAP:
0 - user ok
1 - user not exists or disabled in LDAP
2 - user field are incorrect 

### Зависимости
django-simple-captcha
django-crispy-forms
crispy-bootstrap4
#django_redis ?
###

# Условия в секции #passwords файла vars.py проверяются функцией findall из re
# на данный момент словарь словий не рассчитан на увеличение или уменьшение ключей


#Сообщения об ошибках для пользователя:
Замечена подозрительная активность с участием вашего аккаунта. обратитесь в отдел ИТ для изменения пароля - означает, что пользователь пытается сбросить пароль более одного раза в сутки

#Оставить для лога переменную status_code_sms или для БД

# Если подключаться к ldaps с самоподписным сертификатом, то необходимо в конфигурации ldap на клиенте прописать:
#/etc/ldap/ldap.conf
TLS_REQCERT never