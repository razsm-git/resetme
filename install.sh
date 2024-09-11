#!/bin/bash

apt update && apt install git -y
cd /tmp
git clone https://github.com/razsm-git/resetme.git
cd resetme
xargs apt -y install < requirements_apt
pip install -r requirements_pip --break-system-packages
mkdir -p /resetme/webapp
cd $_
django-admin startproject webapp .
python3 manage.py startapp resetme
cp -r /tmp/resetme /
cp /resetme/samples/gunicorn.* /etc/systemd/system/
cp /resetme/samples/nginx_resetme /etc/nginx/sites-available/nginx_resetme
cp /resetme/samples/redis.conf /etc/redis/redis.conf 
useradd -M -r -U -s /usr/sbin/nologin gunicorn
chown -R www-data:gunicorn /var/log/gunicorn
chmod -R g+w /var/log/gunicorn
ln -s /etc/nginx/sites-available/nginx_resetme /etc/nginx/sites-enabled/nginx_resetme

#postgresql
sudo -u postgres bash -c : && RUNAS="sudo -u postgres"
#Runs bash with commands between '_'
$RUNAS bash<<_
psql 2> /dev/null
CREATE DATABASE resetme_db;
CREATE USER resetme_user WITH PASSWORD 'your_password_here';
ALTER ROLE resetme_user SET client_encoding TO 'utf8';
ALTER ROLE resetme_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE resetme_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE resetme_db TO resetme_user;
ALTER DATABASE resetme_db OWNER TO resetme_user;
\q
_

#enable service
systemctl daemon-reload && systemctl enable gunicorn.service gunicorn.socket nginx redis-server
