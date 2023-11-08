from django import forms
from django.core.validators import RegexValidator, MinLengthValidator
from captcha.fields import CaptchaField
from django.forms import ModelForm
from resetme.models import domain

class UserForm(forms.Form):
    username = forms.CharField(required=True, label = "Логин:", max_length=9, strip=True, validators=[RegexValidator(
        '^[a-z]{5}$|^[a-z]{5}_.{3}$', message="Вы ввели некорректный логин!")], error_messages={'invalid': 'Вы ввели некорректный логин!', 'min_length': 'Вы ввели некорректный логин!', 'max_length':'Вы ввели некорректный логин!'})
    captcha = CaptchaField(required=True, label='Пожалуйста, введите ответ:', error_messages={'invalid': 'Вы ввели неверный ответ!'})

class VerifyPhone(forms.Form):
    code = forms.DecimalField(required=True, label="Код подтверждения:",max_digits=6, validators=[RegexValidator(
        '^[0-9]*$', message="Это не код подтверждения. Не пытайся хитрить.")], error_messages={'invalid': 'Вы ввели неверный ответ!', 'max_digits': 'Код не должен быть длинее 6 цифр'})
    
class DomainForm(ModelForm):
        class Meta:
            model = domain
            fields = ["domain"]