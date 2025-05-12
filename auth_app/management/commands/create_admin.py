from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Create an initial admin user'

    def handle(self, *args, **kwargs):
        username = 'adminRajat'
        password = 'Rajat@321'
        email = 'admin@example.com'
        
        self.stdout.write(f"Creating admin user with username: {username}")

        if not User.objects.filter(username=username).exists():
            print(f"Creating admin user with username: {username}")
            User.objects.create_superuser(username=username, password=password, email=email)
            self.stdout.write(self.style.SUCCESS(f'Successfully created admin user: {username}'))
            self.stdout.write(self.style.SUCCESS(f'Please login with the following credentials:'))
            self.stdout.write(self.style.SUCCESS(f'Username: {username}'))
            self.stdout.write(self.style.SUCCESS(f'Password: {password}'))
        else:
            self.stdout.write(self.style.WARNING('Admin user already exists'))