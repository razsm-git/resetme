from django import forms
from django.core.validators import RegexValidator
from captcha.fields import CaptchaField


class UserForm(forms.Form):
    username= forms.CharField(max_length=9, validators=[RegexValidator(
        '^[a-z]{5}$|^[a-z]{5}_.{3}$', message="Вы ввели некорректный логин!")])
    captcha = CaptchaField(required=False, label='Пожалуйста, введите ответ:', error_messages={'invalid': 'Вы ввели неверный ответ!'})
