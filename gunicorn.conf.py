import multiprocessing

wsgi_app="webapp.wsgi:application"
workers = multiprocessing.cpu_count() * 2 + 1
timeout=120
accesslog="/var/log/gunicorn/access.log"
errorlog="/var/log/gunicorn/error.log"
loglevel="info"
user="gunicorn"
group="gunicorn"
