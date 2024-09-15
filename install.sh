#!/bin/bash
#paths
sed_path=/usr/bin/sed
echo_path=/usr/bin/echo
apt_path=/usr/bin/apt
git_path=/usr/bin/git
xargs_path=/usr/bin/xargs
pip_path=/usr/bin/pip
sleep_path=/usr/bin/sleep
django_admin_path=/usr/local/bin/django-admin
cp_path=/usr/bin/cp
useradd_path=/usr/sbin/useradd
chown_path=/usr/bin/chown
chmod_path=/usr/bin/chmod
ln_path=/usr/bin/ln
sudo_path=/usr/bin/sudo
systemctl_path=/usr/bin/systemctl
rm_path=/usr/bin/rm
python_path=/usr/bin/python3
grep_path=/usr/bin/grep
#Enter your site name(url)
$echo_path -e  "\n\033[33mEnter your site name(url)(example: resetme.example.ru):\n"
read -e -i ""
url=$REPLY
#Enter your company name
$echo_path -e  "\n\033[33mEnter your company name:\n"
read -e -i ""
company_name=$REPLY
#Enter tmp dir
$echo_path -e  "\n\033[33mEnter temp dir name(by default /tmp):\n"
read -e -i "/tmp"
temp_dir=$REPLY
#Enter install dir
$echo_path -e  "\n\033[33mEnter install dir name(by default /resetme):\n"
read -e -i "/resetme"
install_dir=$REPLY
#db host
$echo_path -e  "\n\033[33mEnter host name for database(by default localhost):\n"
read -e -i "localhost"
db_host=$REPLY
#db port
$echo_path -e  "\n\033[33mEnter port for database(by default leave empty):\n"
read -e -i ""
db_port=$REPLY
#db name
$echo_path -e  "\n\033[33mEnter database name(by default resetme_db):\n"
read -e -i "resetme_db"
db_name=$REPLY
#db user
$echo_path -e  "\n\033[33mEnter username for database $db_name (by default resetme_user):\n"
read -e -i "resetme_user"
db_user=$REPLY
#pass function
declare -A passwords
function enter_password {
    #db password
    while true; do
        $echo_path -e  "\n\033[33m"
        local pass1=""
        local pass2=""
        local pass_var1="Enter password for $2: "
        local pass_var2="Re-enter password for $2: "
        # this will take password letter by letter
        local letter1=""
        local letter2=""
        while IFS= read -p "$pass_var1" -r -s -n 1 letter1
        do
            # if you press enter then the condition 
            # is true and it exit the loop
            if [[ $letter1 == $'\0' ]]
            then
                break
            fi
            # the letter will store in password variable
            pass1=${pass1}${letter1}
            # in place of password the asterisk (*) 
            # will printed
            pass_var1="*"
        done
        $echo_path ""
        # this will take password letter by letter (re-enter)
        while IFS= read -p "$pass_var2" -r -s -n 1 letter2
        do
            # if you press enter then the condition 
            # is true and it exit the loop
            if [[ $letter2 == $'\0' ]]
            then
                break
            fi
            # the letter will store in password variable
            pass2=${pass2}${letter2}
            # in place of password the asterisk (*) 
            # will printed
            pass_var2="*"
        done
        $echo_path ""
        if [ "$pass1" = "$pass2" ]; then
            passwords[$1]=$pass1
            break
        else
            $echo_path -e "\033[0m\n\033[0m\033[31mPasswords did not match. Please try again."
        fi
    done
}
# #db password
enter_password db_pass "user $db_user"
db_pass=${passwords[db_pass]}
#sms
$echo_path -e  "\n\033[33mEnter login for sms provider(at this moment only smsc.ru):\n"
read -e -i ""
sms_login=$REPLY
#sms password
enter_password sms_pass "sms provider(at this moment only smsc.ru)"
sms_pass=${passwords[sms_pass]}
#ssl certs
$echo_path -e  "\n\033[33mEnter path to ssl cert for your site name(default /etc/ssl/certificate.cer):\n"
read -e -i "/etc/ssl/certificate.cer"
ssl_cert_path=$REPLY
$echo_path -e  "\n\033[33mEnter path to ssl key cert for your site name(default /etc/ssl/private.key):\n"
read -e -i "/etc/ssl/private.key"
ssl_key_path=$REPLY

#allow subnet for admin acces
$echo_path -e  "\n\033[33mEnter ip or subnet for admin acces to your site(default 10.0.0.0/8):\n"
read -e -i "10.0.0.0/8"
allow_admin_subnet=$REPLY

#return grey color for console
$echo_path -e "\n\033[37m"

cd /tmp
$apt_path update && $apt_path install git -y
$git_path clone https://github.com/razsm-git/resetme.git
if [ $? -eq 0 ]
then
    cd resetme
    $xargs_path $apt_path -y install < requirements_apt
    $pip_path install -r requirements_pip --break-system-packages
    mkdir -p $install_dir/webapp
    cd $_
    $django_admin_path startproject webapp .
    python3 manage.py startapp resetme
    $sleep_path 5
    django_secret_key=$(grep -E 'SECRET_KEY =' $install_dir/webapp/webapp/settings.py | awk '{print $3}')
    $cp_path -r $temp_dir/resetme/* $install_dir/
    cd $install_dir
    #copy sample to config
    $cp_path samples/nginx_resetme /etc/nginx/sites-available/nginx_resetme
    $cp_path samples/gunicorn.* /etc/systemd/system/
    $cp_path samples/vars_sample.py vars.py
    $cp_path samples/secret_sample.py secret.py
    #redis
    $cp_path samples/redis.conf /etc/redis/redis.conf 
    #gunicorn
    $sed_path -i "s@^WorkingDirectory=.*@WorkingDirectory=$install_dir/webapp@g" /etc/systemd/system/gunicorn.service
    $useradd_path -M -r -U -s /usr/sbin/nologin gunicorn
    $chown_path -R www-data:gunicorn /var/log/gunicorn
    $chmod_path -R g+w /var/log/gunicorn
    #nginx
    $sed_path -i "s@server_name .*@server_name $url www.$url;@g" /etc/nginx/sites-available/nginx_resetme
    $sed_path -i "s@ssl_certificate	.*@ssl_certificate $ssl_cert_path;@g" /etc/nginx/sites-available/nginx_resetme
    $sed_path -i "s@ssl_certificate_key	.*@ssl_certificate_key $ssl_key_path;@g" /etc/nginx/sites-available/nginx_resetme
    $sed_path -i "s@if (\$host \!~ \^(example.ru|www.example.ru)$ ).*@if (\$host \!~ \^($url|www.$url)$ ) {@g" /etc/nginx/sites-available/nginx_resetme
    $sed_path -i "s@location /resetme/static/.*@location $install_dir/static/ {@g" /etc/nginx/sites-available/nginx_resetme
    $sed_path -i "s@alias .*@alias $install_dir/webapp/staticfiles;@g" /etc/nginx/sites-available/nginx_resetme
    $sed_path -i "s@allow .*@allow $allow_admin_subnet;@g" /etc/nginx/sites-available/nginx_resetme
    nginx_limit=$($grep_path 'limit_conn_zone' samples/nginx.conf)
    $sed_path -i "/http {.*/a\    $nginx_limit" /etc/nginx/nginx.conf
    $ln_path -s /etc/nginx/sites-available/nginx_resetme /etc/nginx/sites-enabled/nginx_resetme
    #url
    $sed_path -i "s@^site_url.*@site_url = r'https://$url/resetme/'@g" vars.py
    #company name
    $sed_path -i "s@^company_name.*@company_name = '$company_name'@g" vars.py
    #secret key django
    $sed_path -i "s/^secret_key_django =.*/secret_key_django = ''$django_secret_key''/g" secret.py
    #db
    $sed_path -i "s@^resetme_db_host =.*@resetme_db_host = '$db_host'@g" secret.py
    $sed_path -i "s@^resetme_db_port =.*@resetme_db_port = '$db_port'@g" secret.py
    $sed_path -i "s@^resetme_db =.*@resetme_db = '$db_name'@g" secret.py
    $sed_path -i "s@^resetme_db_user =.*@resetme_db_user = '$db_user'@g" secret.py
    $sed_path -i "s@^resetme_db_pass =.*@resetme_db_pass = '$db_pass'@g" secret.py
    #sms
    $sed_path -i "s@^sms_login =.*@sms_login = '$sms_login'@g" secret.py
    $sed_path -i "s@^sms_password =.*@sms_password = '$sms_pass'@g" secret.py
    #allowed hosts
    $sed_path -i "s@^ALLOWED_HOSTS =.*@ALLOWED_HOSTS = \['$url'\]@g" webapp/webapp/settings.py
    #postgresql
    new_table=resetme_domain
    $sudo_path -u postgres bash -c : && RUNAS="$sudo_path -u postgres"
    #Runs bash with commands between '_'
    $RUNAS bash<<_
    psql 2> /dev/null
    CREATE USER $db_user WITH PASSWORD $($echo_path "'$db_pass'");
    ALTER ROLE $db_user SET client_encoding TO 'utf8';
    ALTER ROLE $db_user SET default_transaction_isolation TO 'read committed';
    ALTER ROLE $db_user SET timezone TO 'UTC';
    CREATE DATABASE $db_name OWNER $db_user;
    GRANT ALL PRIVILEGES ON DATABASE $db_name TO $db_user;
    \connect $db_name
    CREATE TABLE public.$new_table (
        id int8 GENERATED BY DEFAULT AS IDENTITY NOT NULL,
        domain_name varchar(50) NOT NULL,
        ad_server varchar(50) NOT NULL,
        base_dn varchar(500) NOT NULL,
        retrieve_attributes varchar(500) NOT NULL,
        search_filter varchar(500) NOT NULL,
        admin_username varchar(50) NOT NULL,
        admin_password varchar(50) NOT NULL,
        "enable" bool NOT NULL,
        CONSTRAINT $($echo_path $new_table)_pkey PRIMARY KEY (id)
    );
    GRANT ALL ON TABLE public.$new_table TO $db_user;
    \q
_
    #enable service
    $systemctl_path daemon-reload && $systemctl_path enable gunicorn.service gunicorn.socket nginx redis-server 2> /dev/null
    $systemctl_path restart redis-server gunicorn.service gunicorn.socket 2> /dev/null
    #remove temp
    $rm_path -rf $temp_dir/resetme/
    cd $install_dir
    #migrate to db
    $python_path $install_dir/webapp/manage.py migrate --fake-initial
    #collect static
    $echo_path 'yes' | $python_path $install_dir/webapp/manage.py collectstatic
    #create superuser
    $echo_path -e "\n\033[32mLet's create a superuser for django:"
    $python_path $install_dir/webapp/manage.py createsuperuser < /dev/tty
    $echo_path -e "\033[42mSuccess!"
    #return grey color for console
    $echo_path -e "\033[0m"
    $echo_path -e "\n\033[37m"
else
    $echo_path -e "\033[0m\n\033[0m\033[31mCan't clone git repo!"
fi

