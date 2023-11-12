from django.db import models
from datetime import datetime
from django.core.validators import RegexValidator


class user(models.Model):
    username = models.CharField(max_length=9)
    first_name = models.CharField(max_length=30)
    phone = models.CharField(max_length=11, validators=[RegexValidator(r'^8[0-9]{10}$')])
    #send_code = models.IntegerField(validators=[RegexValidator(r'^[0-9]{6}$')])
    status = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
    hash = models.BinaryField(max_length=300,editable=True)
    salt = models.BinaryField(max_length=300,editable=True)
    # First element save in DB, second element view in form field
    domain_list = [
    ("your_domain", "your_domain"),
    ("your_domain", "your_domain"),
]
    domain = models.CharField(verbose_name="Выберите домен из списка:", max_length=14, choices=domain_list, default='your_domain')


# class domain(models.Model):
#     # First element save in DB, second element view in form field
#     domain_list = [
#     ("your_domain", "your_domain"),
#     ("your_domain", "your_domain"),
# ]
#     domain = models.CharField(verbose_name="Выберите домен из списка:", max_length=14, choices=domain_list)