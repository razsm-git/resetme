# Generated by Django 5.1.1 on 2024-09-12 06:25

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('resetme', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='user',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=9)),
                ('first_name', models.CharField(max_length=30)),
                ('phone', models.CharField(max_length=12, validators=[django.core.validators.RegexValidator('^+7[0-9]{10}$')])),
                ('status', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now=True)),
                ('hash', models.BinaryField(editable=True, max_length=300)),
                ('salt', models.BinaryField(editable=True, max_length=300)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='resetme.domain')),
            ],
        ),
    ]
