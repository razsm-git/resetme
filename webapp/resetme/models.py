from django.db import models
from django.core.validators import RegexValidator


class domain(models.Model):
    domain_name = models.CharField(max_length=50)
    ad_server = models.CharField(max_length=50, help_text='Example: ldaps://dc1.example.ru:636')
    base_dn = models.CharField(max_length=500, help_text='Example: OU=test,OU=users,DC=example,DC=ru')
    retrieve_attributes = models.CharField(max_length=500, default='mobile,givenName', help_text='with separator ",", but whitout spaces')
    search_filter = models.CharField(max_length=500, help_text='Example: (&(sAMAccountName={})(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=*@example.ru)(mobile=+7*)(!(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=example,DC=ru)))')
    admin_username = models.CharField(max_length=50)
    admin_password = models.CharField(max_length=50)
    enable = models.BooleanField(default=True)

    def __str__(self): 
         return self.domain_name


def get_domain_from_db():
    list_domains = []
    for i in list(domain.objects.all().values_list('domain_name', flat=True).filter(enable=True)):
        list_domains.append((i,i))
    return list_domains

class user(models.Model):
    username = models.CharField(max_length=9)
    first_name = models.CharField(max_length=30)
    phone = models.CharField(max_length=12, validators=[RegexValidator(r'^+7[0-9]{10}$')])
    status = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now=True)
    hash = models.BinaryField(max_length=300,editable=True)
    salt = models.BinaryField(max_length=300,editable=True)
    domain = models.ForeignKey(domain, on_delete=models.PROTECT)

class domain_choise(models.Model):
    domain = models.CharField(verbose_name="Выберите домен из списка:", max_length=15, choices=get_domain_from_db())
