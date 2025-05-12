from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.http import JsonResponse
from django.contrib.auth import login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .models import Profile, UserDocument
from .models import Message, MessageAttachment, GroupMessageAttachment
from .middlewares import auth, guest
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from .models import GroupChat, GroupMessage, UserBlock, UserReport

from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.db.models import Q
from .forms import OTPForm
from .models import FriendRequest

from django.contrib.auth.decorators import login_required
# Create your views here.
from .models import Profile, UserDocument, Post, SavedPost, Comment, Transaction

from .models import  is_user_verified
from .forms import PostForm
from django.contrib import messages
import time
@guest
def initial_page_view(request):
    if request.method == 'POST':
        user_type = request.POST.get('user_type')
        if user_type == 'admin':
            return redirect('admin_login')
        elif user_type == 'user':
            return redirect('login')
    return render(request, 'auth/initial_page.html')

@guest
def admin_login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            if user.is_superuser:
                login(request, user)
                return redirect('admin_dashboard')
            else:
                form.add_error(None, 'You do not have admin privileges')
    else:
        form = AuthenticationForm()
    return render(request, 'auth/admin_login.html', {'form': form})

# @auth
# def admin_dashboard_view(request):
#     if not request.user.is_superuser:
#         return redirect('dashboard')
#     users = User.objects.all()
#     return render(request, 'auth/admin_dashboard.html', {'users': users})

from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model

User = get_user_model()

@login_required
def admin_dashboard_view(request):
    if not request.user.is_staff:
        messages.error(request, "You don't have permission to access the admin dashboard")
        return redirect('dashboard')
    
    # Get users with report counts as annotation
    users = User.objects.all().order_by('-date_joined')
    
    # Get documents that need verification
    pending_documents = UserDocument.objects.filter(status='pending').order_by('submitted_at')
    
    # Get pending reports
    pending_reports = UserReport.objects.filter(status='pending').select_related('reporter', 'reported_user').order_by('-created_at')
    
    return render(request, 'admin/dashboard.html', {
        'users': users,
        'pending_documents': pending_documents,
        'pending_reports': pending_reports,
    })

@login_required
def admin_dashboard(request):
    if not request.user.is_staff:
        return redirect('dashboard')
    
    users = User.objects.all().order_by('-date_joined')
    # pending_documents = UserDocument.objects.filter(status='pending').order_by('submitted_at')
    pending_documents = UserDocument.objects.filter(status='pending').order_by('submitted_at')
    return render(request, 'admin/dashboard.html', {
        'users': users,
        'pending_documents': pending_documents,
    })
# Add this to your views.py
@login_required
def upload_document(request):
    if request.method == 'POST':
        id_proof = request.FILES.get('id_proof')
        address_proof = request.FILES.get('address_proof')
        
        if id_proof and address_proof:
            # Delete existing document if any
            UserDocument.objects.filter(user=request.user).delete()
            
            # Create new document
            UserDocument.objects.create(
                user=request.user,
                id_proof=id_proof,
                address_proof=address_proof,
                status='pending'
            )
            
            messages.success(request, 'Documents uploaded successfully! Awaiting verification.')
            return redirect('dashboard')
    
    return render(request, 'upload_document.html')

@login_required
def verify_document(request, document_id):
    if not request.user.is_staff:
        messages.error(request, "You don't have permission to perform this action")
        return redirect('dashboard')
        
    document = get_object_or_404(UserDocument, id=document_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'approve':
            # Update the document status to 'verified' not 'approved'
            document.status = 'verified'
            document.save()
            
            # Update the profile is_verified field for compatibility
            profile = document.user.profile
            profile.is_verified = True
            profile.save()
            
            messages.success(request, f"Documents for {document.user.username} have been verified successfully")
        elif action == 'reject':
            document.status = 'rejected'
            document.save()
            
            profile = document.user.profile
            profile.is_verified = False
            profile.save()
            
            messages.success(request, f"Documents for {document.user.username} have been rejected")
            
    return redirect('admin_dashboard')

from django.shortcuts import render, redirect
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from .forms import CustomUserCreationForm
from .models import User

import hashlib
import random
@guest
def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Don't activate until OTP verified
            user.save()

            # Generate numeric OTP
            otp = str(random.randint(100000, 999999))

            # Encode UID and hash
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            hash_input = f"{uid}:{otp}"
            otp_hash = hashlib.sha256(hash_input.encode()).hexdigest()

            # Store OTP info in session
            otp_map = request.session.get('otp_map', {})
            otp_map[otp_hash] = {
                'uid': uid,
                'otp': otp,
            }
            request.session['otp_map'] = otp_map

            # Email the OTP
            send_mail(
                'Verify your email',
                f'Your OTP code is: {otp}',
                'from@example.com',
                [user.email],
                fail_silently=False,
            )

            return redirect('verify_otp', otp_hash=otp_hash)
    else:
        form = CustomUserCreationForm()

    return render(request, 'auth/register.html', {'form': form})




@guest
def login_view(request):
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')
    else:
        form = CustomAuthenticationForm()
    return render(request, 'auth/login.html', {'form': form})

@auth
def dashboard_view(request):
    return render(request, 'dashboard.html')

@auth
def profile_view(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    return render(request, 'profile.html', {'profile': profile})

@auth
def change_profile_picture(request):
    if request.method == 'POST':
        profile_picture = request.FILES.get('profile_picture')
        if profile_picture:
            profile = Profile.objects.get(user=request.user)
            profile.profile_picture = profile_picture
            profile.save()
            return redirect('profile')
    return render(request, 'change_profile_picture.html')

@auth
def change_username(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        if username:
            request.user.username = username
            request.user.save()
            return redirect('profile')
    return render(request, 'change_username.html')

def logout_view(request):
    next_page = request.GET.get('next', 'login')
    logout(request)
    return redirect(next_page)


import hashlib
import secrets


@guest
def send_otp_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            otp = f"{secrets.randbelow(1000000):06}"  # 6-digit OTP
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            hash_input = f"{uid}:{otp}"
            otp_hash = hashlib.sha256(hash_input.encode()).hexdigest()

            # Store in otp_map just like in register_view
            otp_map = request.session.get('otp_map', {})
            otp_map[otp_hash] = {
                'uid': uid,
                'otp': otp,
            }
            request.session['otp_map'] = otp_map

            # Email the plain OTP
            send_mail(
                'Your OTP Code',
                f'Your OTP code is: {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            return redirect('verify_otp', otp_hash=otp_hash)
    return render(request, 'auth/send_otp.html')
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            otp = f"{secrets.randbelow(1000000):06}"  # 6-digit OTP
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            hash_input = f"{uid}:{otp}"
            otp_hash = hashlib.sha256(hash_input.encode()).hexdigest()

            # Store in otp_map just like in register_view
            otp_map = request.session.get('otp_map', {})
            otp_map[otp_hash] = {
                'uid': uid,
                'otp': otp,
            }
            request.session['otp_map'] = otp_map

            # Email the plain OTP
            send_mail(
                'Your OTP Code',
                f'Your OTP code is: {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            return redirect('verify_otp', otp_hash=otp_hash)
    return render(request, 'auth/send_otp.html')

# @guest
# def verify_otp_view(request, uid, token):
#     if request.method == 'POST':
#         form = OTPForm(request.POST)
#         if form.is_valid():
#             uid = force_str(urlsafe_base64_decode(uid))
#             user = User.objects.get(pk=uid)
#             if default_token_generator.check_token(user, token):
#                 user.set_password(form.cleaned_data['new_password'])
#                 user.save()
#                 return redirect('login')
#     else:
#         form = OTPForm()
#     return render(request, 'auth/verify_otp.html', {'form': form})

import logging

logger = logging.getLogger(__name__)

@guest
def verify_otp_view(request, otp_hash):
    otp_map = request.session.get('otp_map', {})
    data = otp_map.get(otp_hash)

    if not data:
        messages.error(request, "Invalid or expired OTP link.")
        return redirect('login')

    uid = force_str(urlsafe_base64_decode(data['uid']))
    user = User.objects.get(pk=uid)

    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data['otp']
            if entered_otp == data['otp']:
                new_password = form.cleaned_data['new_password']
                user.set_password(new_password)
                user.is_active = True  # For registration flow
                user.save()

                del otp_map[otp_hash]
                request.session['otp_map'] = otp_map

                messages.success(request, "Password set successfully. Please log in.")
                return redirect('login')
            else:
                messages.error(request, "Incorrect OTP.")
    else:
        form = OTPForm()

    return render(request, 'auth/verify_otp.html', {'form': form})





from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.db.models import Q
from .models import Message 

@login_required
def inbox(request):
    current_user = request.user
    search_query = request.GET.get('search', '')
    receiver_id = request.GET.get('receiver')
    receiver = None
    messages = []

    if search_query:
        users = User.objects.filter(
            Q(email__icontains=search_query) |
            Q(username__icontains=search_query)
        ).exclude(id=current_user.id)
    else:
        users = User.objects.exclude(id=current_user.id)

    if receiver_id:
        receiver = get_object_or_404(User, id=receiver_id)
        messages = Message.objects.filter(
            Q(sender=current_user, receiver=receiver) |
            Q(sender=receiver, receiver=current_user)
        ).order_by('timestamp')

    return render(request, 'messages/inbox.html', {
        'users': users,
        'messages': messages,
        'receiver': receiver,
        'search_query': search_query
    })


@login_required
def send_message(request):
    if request.method == 'POST':
        receiver_id = request.POST.get('receiver')
        content = request.POST.get('content')
        attachment_type = request.POST.get('attachment_type')
        
        if receiver_id and content:
            receiver = get_object_or_404(User, id=receiver_id)
            message = Message.objects.create(
                sender=request.user,
                receiver=receiver,
                content=content
            )
            
            # Handle attachments
            if attachment_type:
                file = None
                if attachment_type == 'image' and 'image' in request.FILES:
                    file = request.FILES['image']
                    file_type = 'image'
                elif attachment_type == 'video' and 'video' in request.FILES:
                    file = request.FILES['video']
                    file_type = 'video'
                elif attachment_type == 'audio' and 'audio' in request.FILES:
                    file = request.FILES['audio']
                    file_type = 'audio'
                elif attachment_type == 'document' and 'document' in request.FILES:
                    file = request.FILES['document']
                    file_type = 'document'
                
                if file:
                    MessageAttachment.objects.create(
                        message=message,
                        file=file,
                        file_type=file_type
                    )
    
    return redirect('inbox')


# ...existing code...



# ...existing code...
@login_required
def dashboard(request):
    # Get the category from query parameters
    current_category = request.GET.get('category')
    
    # Filter posts by category if specified
    if current_category:
        posts = Post.objects.filter(
            category=current_category, 
            available_quantity__gt=0
        ).order_by('-created_at')
    else:
        posts = Post.objects.filter(
            available_quantity__gt=0
        ).order_by('-created_at')
    
    # Get IDs of posts saved by the user for UI highlighting
    saved_post_ids = SavedPost.objects.filter(user=request.user).values_list('post_id', flat=True)
    
    # Use your original is_user_verified function
    is_user_verified_value = is_user_verified(request.user)
    
    return render(request, 'dashboard.html', {
        'posts': posts,
        'saved_post_ids': saved_post_ids,
        'current_category': current_category,
        'is_user_verified': is_user_verified_value,
    })

# def dashboard(request):
#     # Get category filter from query params
#     category = request.GET.get('category')
    
#     # Enhanced debugging to identify the issue
#     print(f"Request category: {category}")
    
#     # Show all existing categories and their post counts
#     all_categories = Post.objects.values_list('category', flat=True).distinct()
#     print(f"Categories in database: {list(all_categories)}")
#     for cat in all_categories:
#         count = Post.objects.filter(category=cat).count()
#         print(f"Category '{cat}': {count} posts")
    
#     # Case-insensitive filtering to handle potential case mismatches
#     if category and category != 'all':
#         posts = Post.objects.filter(category__iexact=category).order_by('-created_at')
#         print(f"Posts found for '{category}': {posts.count()}")
        
#         # If no posts found with exact match, try again with case-insensitive search
#         if posts.count() == 0:
#             print("No exact matches found, trying case-insensitive search")
#             posts = Post.objects.filter(category__icontains=category).order_by('-created_at')
#             print(f"Case-insensitive search found: {posts.count()} posts")
#     else:
#         posts = Post.objects.all().order_by('-created_at')
    
#     # Check if user has verified documents
#     is_verified = is_user_verified(request.user)
    
#     # Get IDs of saved posts for the current user
#     saved_post_ids = []
#     if request.user.is_authenticated:
#         saved_post_ids = SavedPost.objects.filter(user=request.user).values_list('post_id', flat=True)
    
#     # Add debugging info to the response
#     debug_info = {
#         'requested_category': category,
#         'found_posts': posts.count(),
#         'available_categories': list(all_categories)
#     }
    
#     return render(request, 'dashboard.html', {
#         'posts': posts,
#         'is_user_verified': is_verified,
#         'saved_post_ids': saved_post_ids,
#         'current_category': category,
#         'debug_info': debug_info,  # Pass debugging info to template
#     })


# ...existing code...

def post_detail(request, post_id):
    post = get_object_or_404(Post, pk=post_id)
    saved_post_ids = []
    comments = Comment.objects.filter(post=post).order_by('-created_at')
    
    if request.user.is_authenticated:
        # Get all saved post IDs for the current user
        saved_post_ids = SavedPost.objects.filter(user=request.user).values_list('post_id', flat=True)
    
    context = {
        'post': post,
        'saved_post_ids': saved_post_ids,
        'comments': comments,
    }
    return render(request, 'post_detail.html', context)

# Add to views.py
from django.contrib.auth.models import User
from django.shortcuts import redirect

def message_user(request, user_id):
    recipient = get_object_or_404(User, id=user_id)
    # Logic to redirect to a messaging form or directly create a new message thread
    return redirect('inbox')  # Or to a specific messaging page

# ...existing code...

@login_required
def user_profile(request, user_id):
    profile_user = get_object_or_404(User, id=user_id)
    user_posts = Post.objects.filter(user=profile_user).order_by('-created_at')
    
    # Check if user has verified documents
    profile_user.is_verified = is_user_verified(profile_user)
    
    return render(request, 'user_profile.html', {
        'profile_user': profile_user,
        'user_posts': user_posts
    })

@login_required
def search_users(request):
    query = request.GET.get('q', '')
    if query:
        users = User.objects.filter(
            Q(username__icontains=query) | 
            Q(email__icontains=query)
        ).exclude(id=request.user.id)
    else:
        users = User.objects.none()
        
    return render(request, 'search_users.html', {
        'users': users,
        'query': query
    })

@login_required
def create_group(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        members = request.POST.getlist('members')
        if name and members:
            group = GroupChat.objects.create(name=name, created_by=request.user)
            group.members.add(*User.objects.filter(id__in=members))
            group.members.add(request.user)
            return redirect('group_chat', group_id=group.id)
    users = User.objects.exclude(id=request.user.id)
    return render(request, 'messages/create_group.html', {'users': users})

@login_required
def group_chat(request, group_id):
    group = get_object_or_404(GroupChat, id=group_id)
    if request.user not in group.members.all():
        return redirect('dashboard')
    messages = GroupMessage.objects.filter(group=group).order_by('timestamp')
    return render(request, 'messages/group_chat.html', {
        'group': group,
        'messages': messages
    })

@login_required
def send_group_message(request, group_id):
    group = get_object_or_404(GroupChat, id=group_id)
    if request.method == 'POST' and request.user in group.members.all():
        content = request.POST.get('content')
        attachment_type = request.POST.get('attachment_type')
        
        if content:
            message = GroupMessage.objects.create(
                group=group,
                sender=request.user,
                content=content
            )
            
            # Handle attachments
            if attachment_type:
                file = None
                if attachment_type == 'image' and 'image' in request.FILES:
                    file = request.FILES['image']
                    file_type = 'image'
                elif attachment_type == 'video' and 'video' in request.FILES:
                    file = request.FILES['video']
                    file_type = 'video'
                elif attachment_type == 'audio' and 'audio' in request.FILES:
                    file = request.FILES['audio']
                    file_type = 'audio'
                elif attachment_type == 'document' and 'document' in request.FILES:
                    file = request.FILES['document']
                    file_type = 'document'
                
                if file:
                    GroupMessageAttachment.objects.create(
                        message=message,
                        file=file,
                        file_type=file_type
                    )
                    
    return redirect('group_chat', group_id=group.id)


@login_required
def my_posts(request):
    posts = Post.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'my_posts.html', {
        'posts': posts,
        'is_user_verified': is_user_verified(request.user)
    })

@login_required
def saved_posts(request):
    saved_items = SavedPost.objects.filter(user=request.user).order_by('-saved_at')
    return render(request, 'saved_posts.html', {
        'saved_items': saved_items,
        'is_user_verified': is_user_verified(request.user)
    })

@login_required
def save_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    
    # Check if post is already saved
    saved = SavedPost.objects.filter(user=request.user, post=post).first()
    
    if saved:
        # Post was already saved, so remove it
        saved.delete()
        messages.success(request, "Post removed from saved items")
    else:
        # Post wasn't saved, so save it
        SavedPost.objects.create(user=request.user, post=post)
        messages.success(request, "Post added to saved items")
    
    # Redirect back to the previous page
    return redirect(request.META.get('HTTP_REFERER', 'dashboard'))

# Add these views for comment functionality

@login_required
def add_comment(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            Comment.objects.create(
                post=post,
                user=request.user,
                content=content
            )
            messages.success(request, "Comment added successfully")
        else:
            messages.error(request, "Comment cannot be empty")
    
    return redirect(request.META.get('HTTP_REFERER', 'dashboard'))

@login_required
def delete_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id)
    
    # Only allow the comment owner to delete it
    if request.user == comment.user:
        comment.delete()
        messages.success(request, "Comment deleted successfully")
    else:
        messages.error(request, "You don't have permission to delete this comment")
    
    return redirect(request.META.get('HTTP_REFERER', 'dashboard'))

# Add these views for post management

@login_required
def edit_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    
    # Check if the user is the owner of this post
    if request.user != post.user:
        messages.error(request, "You don't have permission to edit this post")
        return redirect('dashboard')
    
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        price = request.POST.get('price')
        
        # Update post details
        post.title = title
        post.description = description
        post.price = price
        
        # Handle image upload if provided
        if 'image' in request.FILES:
            post.image = request.FILES['image']
        
        post.save()
        messages.success(request, "Post updated successfully")
        return redirect('my_posts')
    
    return render(request, 'edit_post.html', {'post': post})

@login_required
def delete_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    
    # Check if the user is the owner of this post
    if request.user != post.user:
        messages.error(request, "You don't have permission to delete this post")
        return redirect('dashboard')
    
    if request.method == 'POST':
        post.delete()
        messages.success(request, "Post deleted successfully")
    
    return redirect('my_posts')

# ...existing code...

@login_required
def send_friend_request(request, user_id):
    receiver = get_object_or_404(User, id=user_id)
    
    if request.user == receiver:
        messages.error(request, "You can't send a friend request to yourself")
        return redirect('user_profile', user_id=user_id)
    
    # Check if receiver has blocked the sender
    if UserBlock.objects.filter(blocker=receiver, blocked=request.user).exists():
        messages.error(request, "Unable to send friend request")
        return redirect('user_profile', user_id=user_id)
    
    # Check if there's an existing request
    existing_request = FriendRequest.objects.filter(
        sender=request.user, 
        receiver=receiver
    ).first()
    
    if existing_request:
        messages.info(request, f"You already sent a friend request to {receiver.username}")
    else:
        # Check if there's a request in the opposite direction
        opposite_request = FriendRequest.objects.filter(
            sender=receiver, 
            receiver=request.user,
            status='pending'
        ).first()
        
        if opposite_request:
            # Auto-accept the opposite request
            opposite_request.status = 'accepted'
            opposite_request.save()
            messages.success(request, f"You are now friends with {receiver.username}")
        else:
            # Create a new friend request
            FriendRequest.objects.create(sender=request.user, receiver=receiver)
            messages.success(request, f"Friend request sent to {receiver.username}")
    
    return redirect('user_profile', user_id=user_id)

@login_required
def respond_to_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, id=request_id, receiver=request.user)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'accept':
            friend_request.status = 'accepted'
            friend_request.save()
            messages.success(request, f"You are now friends with {friend_request.sender.username}")
        elif action == 'reject':
            friend_request.status = 'rejected'
            friend_request.save()
            messages.success(request, f"Friend request from {friend_request.sender.username} rejected")
    
    return redirect('friend_requests')

@login_required
def friend_requests(request):
    # Get pending friend requests
    pending_requests = FriendRequest.objects.filter(
        receiver=request.user,
        status='pending'
    ).order_by('-created_at')
    
    # Get list of friends (accepted friend requests)
    sent_accepted = FriendRequest.objects.filter(
        sender=request.user,
        status='accepted'
    ).values_list('receiver_id', flat=True)
    
    received_accepted = FriendRequest.objects.filter(
        receiver=request.user,
        status='accepted'
    ).values_list('sender_id', flat=True)
    
    friend_ids = list(sent_accepted) + list(received_accepted)
    friends = User.objects.filter(id__in=friend_ids)
    
    return render(request, 'friends/friend_requests.html', {
        'pending_requests': pending_requests,
        'friends': friends
    })

@login_required
def block_user(request, user_id):
    user_to_block = get_object_or_404(User, id=user_id)
    
    if request.user == user_to_block:
        messages.error(request, "You cannot block yourself")
        return redirect('user_profile', user_id=user_id)
    
    # Check if already blocked
    block, created = UserBlock.objects.get_or_create(blocker=request.user, blocked=user_to_block)
    
    if created:
        # Remove any existing friend connections
        FriendRequest.objects.filter(
            (Q(sender=request.user) & Q(receiver=user_to_block)) | 
            (Q(sender=user_to_block) & Q(receiver=request.user))
        ).delete()
        
        messages.success(request, f"You have blocked {user_to_block.username}")
    else:
        messages.info(request, f"You have already blocked {user_to_block.username}")
    
    return redirect('user_profile', user_id=user_id)

@login_required
def unblock_user(request, block_id):
    block = get_object_or_404(UserBlock, id=block_id, blocker=request.user)
    unblocked_user = block.blocked
    block.delete()
    messages.success(request, f"You have unblocked {unblocked_user.username}")
    return redirect('blocked_users')

@login_required
def blocked_users(request):
    blocked_users = UserBlock.objects.filter(blocker=request.user).select_related('blocked')
    return render(request, 'friends/blocked_users.html', {
        'blocked_users': blocked_users
    })

@login_required
def report_user(request, user_id):
    user_to_report = get_object_or_404(User, id=user_id)
    
    if request.user == user_to_report:
        messages.error(request, "You cannot report yourself")
        return redirect('user_profile', user_id=user_id)
    
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        details = request.POST.get('details', '')
        
        if report_type:
            UserReport.objects.create(
                reporter=request.user,
                reported_user=user_to_report,
                report_type=report_type,
                details=details
            )
            messages.success(request, f"Your report against {user_to_report.username} has been submitted")
            return redirect('user_profile', user_id=user_id)
    
    return render(request, 'friends/report_user.html', {
        'user_to_report': user_to_report,
    })

@login_required
def admin_reports(request):
    if not request.user.is_staff:
        return redirect('dashboard')
    
    reports = UserReport.objects.filter(status='pending').order_by('-created_at')
    return render(request, 'admin/reports.html', {
        'reports': reports
    })

@login_required
def handle_report(request, report_id):
    if not request.user.is_staff:
        return redirect('dashboard')
    
    report = get_object_or_404(UserReport, id=report_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action in ['reviewed', 'resolved', 'dismissed']:
            report.status = action
            report.save()
            messages.success(request, f"Report marked as {action}")
        
        # Add option to block the reported user account if needed
        if 'block_user' in request.POST:
            reported_user = report.reported_user
            reported_user.is_active = False  # This will prevent the user from logging in
            reported_user.save()
            messages.success(request, f"User {reported_user.username} has been blocked from the platform")
    
    return redirect('admin_reports')


def friend_requests_count(request):
    if request.user.is_authenticated:
        pending_count = FriendRequest.objects.filter(
            receiver=request.user,
            status='pending'
        ).count()
        return {'pending_requests_count': pending_count}
    return {'pending_requests_count': 0}

@login_required
def admin_manage_user(request, user_id):
    if not request.user.is_staff:
        messages.error(request, "You don't have permission to perform this action")
        return redirect('dashboard')
    
    user_to_manage = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        # Update user status
        user_to_manage.is_active = 'is_active' in request.POST
        user_to_manage.save()
        
        # Update profile settings
        profile = user_to_manage.profile
        profile.is_verified = 'is_verified' in request.POST
        profile.can_post = 'can_post' in request.POST
        profile.save()
        
        messages.success(request, f"User {user_to_manage.username}'s settings updated successfully")
        
    return redirect('admin_dashboard')
@login_required
def buy_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user_profile = request.user.profile
    
    # Initial checks before sending OTP
    if post.available_quantity <= 0:
        messages.error(request, "This item is no longer available.")
        return redirect('dashboard')
    
    if user_profile.wallet_balance < post.price:
        messages.error(request, "Insufficient funds in your wallet.")
        return redirect('dashboard')
    
    # Instead of processing immediately, redirect to OTP flow
    if request.method == 'POST':
        # Create a hidden form to pass post_id to the OTP view
        return render(request, 'auth/confirm_purchase.html', {'post': post})
        
    return redirect('dashboard')

from decimal import Decimal
@login_required
def add_funds(request):
    if request.method == 'POST':
        amount = Decimal(request.POST.get('amount', 0))
        if amount > 0:
            user_profile = request.user.profile
            user_profile.wallet_balance += amount
            user_profile.save()
            messages.success(request, f"${amount} added to your wallet successfully.")
        else:
            messages.error(request, "Please enter a valid amount.")
            
    return render(request, 'add_funds.html')



@login_required
def my_purchases(request):
    # Get all transactions where the current user is the buyer
    purchases = Transaction.objects.filter(buyer=request.user).order_by('-timestamp')
    
    # Get unique posts from these transactions
    purchased_posts = set(transaction.post for transaction in purchases)
    
    return render(request, 'my_purchases.html', {
        'purchases': purchases,
        'purchased_posts': purchased_posts
    })


@login_required
def create_post(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        price = request.POST.get('price')
        category = request.POST.get('category')
        quantity = request.POST.get('quantity', 1)
        image = request.FILES.get('image')
        
        # Debug output
        print(f"Creating post with title: {title}, category: {category}")
        
        # Validate the category
        valid_categories = ['Electronics', 'Furniture', 'Clothing', 'Books', 'Other']
        if not category or category not in valid_categories:
            category = 'Other'  # Default fallback
        
        # Create the post
        post = Post.objects.create(
            user=request.user,
            title=title,
            description=description,
            price=price,
            category=category,
            available_quantity=quantity,
            image=image
        )
        
        messages.success(request, f"Your item '{title}' has been posted successfully!")
        return redirect('dashboard')
        
    return redirect('dashboard')
def process_purchase(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user_profile = request.user.profile
    
    # Check if post is available
    if post.available_quantity <= 0:
        messages.error(request, "This item is no longer available.")
        return redirect('dashboard')
    
    # Check if user has enough balance
    if user_profile.wallet_balance >= post.price:
        # Create a transaction record
        Transaction.objects.create(
            buyer=request.user,
            seller=post.user,
            post=post,
            amount=post.price
        )
        
        # Update wallet balances
        user_profile.wallet_balance -= post.price
        user_profile.save()
        
        seller_profile = post.user.profile
        seller_profile.wallet_balance += post.price
        seller_profile.save()
        
        # Update post quantity
        post.available_quantity -= 1
        post.save()
        
        # If quantity is now zero, mark as sold
        if post.available_quantity <= 0:
            post.is_sold = True
            post.save()
        
        messages.success(request, f"Transaction successful! You've purchased {post.title}!")
    else:
        messages.error(request, "Insufficient funds in your wallet.")
        
    return redirect('dashboard')

@login_required
def send_transaction_otp(request):
    if request.method == 'POST':
        post_id = request.POST.get('post_id')
        # Store post_id in session for later use
        request.session['pending_transaction_post_id'] = post_id
        
        # Get user's email
        email = request.user.email
        
        # Generate OTP
        otp = f"{secrets.randbelow(1000000):06}"  # 6-digit OTP
        uid = urlsafe_base64_encode(force_bytes(request.user.pk))
        hash_input = f"{uid}:{otp}"
        otp_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        # Store in otp_map
        otp_map = request.session.get('otp_map', {})
        otp_map[otp_hash] = {
            'uid': uid,
            'otp': otp,
            'purpose': 'transaction',
            'post_id': post_id,
            'expires': time.time() + 300,  # 5 minutes expiry
        }
        request.session['otp_map'] = otp_map

        # Email the OTP
        send_mail(
            'Transaction Verification OTP',
            f'Your transaction verification OTP code is: {otp}',
            'from@example.com',
            [email],
            fail_silently=False,
        )

        return redirect('verify_transaction_otp', otp_hash=otp_hash)
    
    return redirect('dashboard')


@login_required
def verify_transaction_otp(request, otp_hash):
    otp_map = request.session.get('otp_map', {})
    data = otp_map.get(otp_hash)

    if not data or data.get('purpose') != 'transaction':
        messages.error(request, "Invalid or expired OTP.")
        return redirect('dashboard')

    # Check if OTP has expired
    if time.time() > data.get('expires', 0):
        del otp_map[otp_hash]
        request.session['otp_map'] = otp_map
        messages.error(request, "OTP has expired. Please try again.")
        return redirect('dashboard')

    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if entered_otp == data['otp']:
            # OTP is correct, process the transaction
            post_id = data['post_id']
            
            # Clean up the OTP data
            del otp_map[otp_hash]
            request.session['otp_map'] = otp_map
            
            # Process the actual purchase
            return process_purchase(request, post_id)
        else:
            messages.error(request, "Incorrect OTP. Please try again.")

    return render(request, 'auth/verify_transaction_otp.html')