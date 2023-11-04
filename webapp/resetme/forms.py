from django import forms
from django.core.validators import RegexValidator
from captcha.fields import CaptchaField


class UserForm(forms.Form):
    captcha = CaptchaField()
    username= forms.CharField(max_length=9, validators=[RegexValidator(
        '^[a-z]{5}$|^[a-z]{5}_.{3}$', message="Вы ввели некорректный логин!")])
