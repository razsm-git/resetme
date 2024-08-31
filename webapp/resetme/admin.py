from django.contrib import admin
from resetme.models import domain  
from django.contrib.messages import constants as messages
from django import forms

# Register your models here.

class DomainAdminForm(forms.ModelForm):
    class Meta:
        model = domain
        widgets = {
            'admin_password' : forms.PasswordInput(),
        }
        fields = '__all__'

@admin.register(domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'ad_server', 'enable')
    ordering = ['domain_name']
    list_per_page = 20
    actions = ['set_status_enable','set_status_disable']
    form=DomainAdminForm
    #action enable
    @admin.action(description="Set enable")
    def set_status_enable(self, request, queryset):
        count = queryset.update(enable=True)
        self.message_user(request, f"{count} domain was enabled", messages.SUCCESS)
    #action disable
    @admin.action(description="Set disable")
    def set_status_disable(self, request, queryset):
        count = queryset.update(enable=False)
        self.message_user(request, f"{count} domain was disabled", messages.WARNING)

