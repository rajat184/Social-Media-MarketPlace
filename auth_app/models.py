from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
from django.conf import settings
import base64
import os

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', default='default.jpg')
    is_verified = models.BooleanField(default=False)
    can_post = models.BooleanField(default=True)
    wallet_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    def __str__(self):
        return self.user.username
    

def message_attachment_path(instance, filename):
    # File will be uploaded to MEDIA_ROOT/messages/user_<id>/<filename>
    return 'messages/user_{0}/{1}'.format(instance.message.sender.id, filename)

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    content = models.BinaryField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

    def save(self, *args, **kwargs):
        if isinstance(self.content, str):
            f = Fernet(settings.ENCRYPTION_KEY)
            self.content = f.encrypt(self.content.encode())
        super().save(*args, **kwargs)

    @property
    def decrypted_content(self):
        try:
            f = Fernet(settings.ENCRYPTION_KEY)
            return f.decrypt(self.content).decode()
        except Exception as e:
            return "Error decrypting message"
        
class MessageAttachment(models.Model):
    message = models.ForeignKey(Message, related_name='attachments', on_delete=models.CASCADE)
    file = models.FileField(upload_to=message_attachment_path)
    file_type = models.CharField(max_length=20)  # 'image', 'video', 'document', etc.
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Attachment for message {self.message.id}"
    
    def filename(self):
        return os.path.basename(self.file.name)
    
    def is_image(self):
        return self.file_type == 'image'
    
    def is_video(self):
        return self.file_type == 'video'# Add this function after the message_attachment_path function

def group_message_attachment_path(instance, filename):
    # File will be uploaded to MEDIA_ROOT/group_messages/group_<id>/<filename>
    return 'group_messages/group_{0}/{1}'.format(instance.message.group.id, filename)

class GroupChat(models.Model):
    name = models.CharField(max_length=100)
    members = models.ManyToManyField(User, related_name='group_chats')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class GroupMessage(models.Model):
    group = models.ForeignKey(GroupChat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.sender.username} in {self.group.name}'

class GroupMessageAttachment(models.Model):
    message = models.ForeignKey(GroupMessage, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to=group_message_attachment_path)
    file_type = models.CharField(max_length=20)  # 'image', 'video', 'document', etc.
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Attachment for group message {self.message.id}"
    
    def filename(self):
        return os.path.basename(self.file.name)
    
    def is_image(self):
        return self.file_type == 'image'
    
    def is_video(self):
        return self.file_type == 'video'
    

    
# In models.py
class UserDocument(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='auth_app_document')
    id_proof = models.FileField(upload_to='documents/id_proofs/', null=True, blank=True)
    address_proof = models.FileField(upload_to='documents/address_proofs/', null=True, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    verification_notes = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.user.username}'s documents ({self.status})"

    class Meta:
        app_label = 'auth_app'

# ...existing code...

# ...existing code...

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    image = models.ImageField(upload_to='post_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    quantity = models.PositiveIntegerField(default=1)
    available_quantity = models.PositiveIntegerField(default=1)
    is_sold = models.BooleanField(default=False)
    sold_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='purchased_items')
    
    # In the Post model class:
    CATEGORY_CHOICES = [
        ('Electronics', 'Electronics'),
        ('Furniture', 'Furniture'),
        ('Clothing', 'Clothing'),
        ('Books', 'Books'),
        ('Other', 'Other'),
    ]

    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Other')
    def __str__(self):
        return self.title
    
    class Meta:
        ordering = ['-created_at']
    def is_sold_out(self):
        return self.available_quantity <= 0
        
    def update_availability(self):
        self.is_sold = self.available_quantity <= 0
        self.save()

    def save(self, *args, **kwargs):
        # This will be handled in the view for better user experience
        super().save(*args, **kwargs)
    

# Add this method to check if a user is verified
def is_user_verified(user):
    """Check if user has verified documents"""
    try:
        return UserDocument.objects.filter(user=user, status='verified').exists()
    except:
        return False

class SavedPost(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    saved_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'post')

# Add this model below the Post model

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f'Comment by {self.user.username} on {self.post.title}'

# ...existing code...

# ...existing models...

class FriendRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    )
    
    sender = models.ForeignKey(User, related_name='sent_requests', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_requests', on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('sender', 'receiver')
    
    def __str__(self):
        return f"{self.sender.username} to {self.receiver.username} - {self.status}"
    
class UserBlock(models.Model):
    blocker = models.ForeignKey(User, related_name='blocking', on_delete=models.CASCADE)
    blocked = models.ForeignKey(User, related_name='blocked_by', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('blocker', 'blocked')
    
    def __str__(self):
        return f"{self.blocker.username} blocked {self.blocked.username}"

class UserReport(models.Model):
    REPORT_CHOICES = (
        ('spam', 'Spam'),
        ('harassment', 'Harassment'),
        ('inappropriate', 'Inappropriate Content'),
        ('impersonation', 'Impersonation'),
        ('scam', 'Scam or Fraud'),
        ('other', 'Other'),
    )
    
    reporter = models.ForeignKey(User, related_name='reported', on_delete=models.CASCADE)
    reported_user = models.ForeignKey(User, related_name='reports', on_delete=models.CASCADE)
    report_type = models.CharField(max_length=20, choices=REPORT_CHOICES)
    details = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=(
        ('pending', 'Pending'),
        ('reviewed', 'Reviewed'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed')
    ), default='pending')
    
    def __str__(self):
        return f"{self.reporter.username} reported {self.reported_user.username} - {self.report_type}"
    

class Transaction(models.Model):
    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchases')
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sales')
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.buyer.username} purchased {self.post.title} from {self.seller.username}"
    
class Transaction(models.Model):
    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchases')
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sales')
    post = models.ForeignKey('Post', on_delete=models.CASCADE)  # Use string reference if Post is defined later
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.buyer.username} purchased {self.post.title} from {self.seller.username}"
    

from django.db import migrations

def fix_post_categories(apps, schema_editor):
    Post = apps.get_model('auth_app', 'Post')
    
    # Check for posts with empty categories and set them to 'Electronics'
    empty_categories = Post.objects.filter(category__isnull=True) | Post.objects.filter(category='')
    empty_categories.update(category='Electronics')
    
    # Standardize category capitalization
    for post in Post.objects.all():
        if post.category and post.category.lower() == 'electronics':
            post.category = 'Electronics'
            post.save()
        elif post.category and post.category.lower() == 'furniture':
            post.category = 'Furniture'
            post.save()
        elif post.category and post.category.lower() == 'clothing':
            post.category = 'Clothing'
            post.save()
        elif post.category and post.category.lower() == 'books':
            post.category = 'Books'
            post.save()
        elif post.category and post.category.lower() == 'other':
            post.category = 'Other'
            post.save()

class Migration(migrations.Migration):
    dependencies = [
        ('auth_app', 'your_last_migration'),  # Replace with your actual last migration
    ]

    operations = [
        migrations.RunPython(fix_post_categories),
    ]