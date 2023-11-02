from django import forms
from django.core.validators import RegexValidator


class UserForm(forms.Form):
    username= forms.CharField(max_length=9, validators=[RegexValidator(
        '^[a-z]{5}$|^[a-z]{5}_.{3}$', message="Вы ввели некорректный логин!")])
