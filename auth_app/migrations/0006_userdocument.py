# Generated by Django 5.1.4 on 2025-03-10 17:27

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0005_alter_message_content'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('id_proof', models.FileField(blank=True, null=True, upload_to='documents/id_proofs/')),
                ('address_proof', models.FileField(blank=True, null=True, upload_to='documents/address_proofs/')),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('verified', 'Verified'), ('rejected', 'Rejected')], default='pending', max_length=10)),
                ('verification_notes', models.TextField(blank=True, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='auth_app_document', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
