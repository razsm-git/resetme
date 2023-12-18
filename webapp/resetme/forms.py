from django import forms
from django.core.validators import RegexValidator
from captcha.fields import CaptchaField
from django.forms import ModelForm
from resetme.models import user
from vars import login_validator, sms_code_validator

class UserForm(forms.Form):
    username = forms.CharField(required=True, label = "Логин:", max_length=9, strip=True, validators=[RegexValidator(
        login_validator, message="Вы ввели некорректный логин!")], error_messages={'invalid': 'Вы ввели некорректный логин!'})
    captcha = CaptchaField(required=True, label='Пожалуйста, введите ответ:', error_messages={'invalid': 'Вы ввели неверный ответ!'})

class VerifyPhone(forms.Form):
    code = forms.CharField(required=False, label="", validators=[RegexValidator(
        sms_code_validator, message="Это не код подтверждения. Не пытайся хитрить.")], error_messages={'invalid': 'Вы ввели неверный код!'})

# Import from model    
class DomainForm(ModelForm):
    class Meta:
        model = user
        fields = ["domain"]

class ChangePassword(forms.Form):
     new_password = forms.CharField(required=True, label="Введите новый пароль:", widget=forms.PasswordInput)
     confirm_new_password = forms.CharField(required=True, label="Подтверждение пароля:", widget=forms.PasswordInput)
