# Generated by Django 5.1.3 on 2024-12-02 08:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message', '0007_message_payment'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='payment',
            field=models.CharField(max_length=50),
        ),
    ]
