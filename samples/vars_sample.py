#change
site_url = r'https://resetme.example.ru/resetme/'
company_name = ''
title_name = 'Страница сброса пароля'
#background pages color
background_color_index = '#1d1f10;'
background_color_domain_choice = '#005773;'
background_color_verify_phone = '#4d2637;'
background_color_change_password = '#006c73;'
background_color_success = '#00735b;'
# Time in minutes for sync dc
dc_time_sync = 15
###
login_validator = '^[a-z]{5}$'
sms_code_validator = '^[0-9]{6}$'

# Count of post form with wrong data(ex., username)
count_of_fails_form_threshold = 3
# Count of post form with sms code
count_of_fails_code_threshold = 3

# hash
urandom_bytes = 16
algoritm = 'sha256'
coding = 'utf-8'
iter = 100000
dklen = 128

# passwords validation
conditions = {'len': 8, 'upper': '[A-Z]', 'lower': '[a-z]', 'number': '[0-9]', 'history': 10, 'change_per_day': 1}

#Redis settings
redis_host = 'localhost'
redis_port = 6379
db = 1
redis_sock = '/var/run/redis/redis.sock'
#TTL entry in redis
redis_ttl = 600
redis_ttl_sms_code = 120