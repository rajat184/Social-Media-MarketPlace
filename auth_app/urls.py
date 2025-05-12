from django.urls import path
from .views import (
    initial_page_view, admin_login_view, admin_dashboard_view, register_view, login_view, dashboard_view,
    profile_view, change_profile_picture, change_username, logout_view, send_otp_view, verify_otp_view, inbox, send_message,
    admin_dashboard, verify_document, upload_document, dashboard, create_post, post_detail, message_user, user_profile, search_users, create_group, group_chat, send_group_message,
    my_posts, saved_posts, save_post, add_comment, delete_comment, edit_post, delete_post,
    send_friend_request, friend_requests, respond_to_friend_request, block_user, unblock_user, blocked_users, report_user, admin_reports, handle_report, admin_manage_user,buy_post, add_funds,my_purchases, send_transaction_otp, verify_transaction_otp
)



urlpatterns = [
    path('', initial_page_view, name='initial_page'),
    path('auth/admin/login/', admin_login_view, name='admin_login'),
    path('auth/admin/dashboard/', admin_dashboard_view, name='admin_dashboard'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    # path('dashboard/', dashboard_view, name='dashboard'),
    path('profile/', profile_view, name='profile'),
    path('profile/change-picture/', change_profile_picture, name='change_profile_picture'),
    path('profile/change-username/', change_username, name='change_username'),
    path('logout/', logout_view, name='logout'),
    path('send-otp/', send_otp_view, name='send_otp'),
    path('verify-otp/<str:otp_hash>/', verify_otp_view, name='verify_otp'),
    path('inbox/', inbox, name='inbox'),
    path('send-message/', send_message, name='send_message'),
    # path('admin/dashboard/', admin_dashboard, name='admin_dashboard'),
    path('auth/admin/dashboard/', admin_dashboard_view, name='admin_dashboard'),
    path('auth/admin/verify-document/<int:document_id>/', verify_document, name='verify_document'),
    path('documents/upload/', upload_document, name='upload_document'),
    path('dashboard/', dashboard, name='dashboard'),
    path('post/create/', create_post, name='create_post'),
    path('post/<int:post_id>/', post_detail, name='post_detail'),
    # Add to urls.py if not already there
    path('message-user/<int:user_id>/', message_user, name='message_user'),
    path('user-profile/<int:user_id>/', user_profile, name='user_profile'),
    path('search-users/', search_users, name='search_users'),
    path('groups/create/', create_group, name='create_group'),
    path('groups/<int:group_id>/', group_chat, name='group_chat'),
    path('groups/<int:group_id>/send/', send_group_message, name='send_group_message'),
    # Add these URL patterns

    path('my-posts/', my_posts, name='my_posts'),
    path('saved-posts/', saved_posts, name='saved_posts'),
    # Existing patterns...
    path('post/<int:post_id>/save/', save_post, name='save_post'),
    path('post/<int:post_id>/comment/', add_comment, name='add_comment'),
    path('comment/<int:comment_id>/delete/', delete_comment, name='delete_comment'),
    path('post/<int:post_id>/edit/', edit_post, name='edit_post'),
    path('post/<int:post_id>/delete/', delete_post, name='delete_post'),

    # Friend request paths
    path('send-friend-request/<int:user_id>/', send_friend_request, name='send_friend_request'),
    path('friend-requests/', friend_requests, name='friend_requests'),
    path('respond-friend-request/<int:request_id>/', respond_to_friend_request, name='respond_to_friend_request'),
    
    # Block user paths
    path('block-user/<int:user_id>/', block_user, name='block_user'),
    path('unblock-user/<int:block_id>/', unblock_user, name='unblock_user'),
    path('blocked-users/', blocked_users, name='blocked_users'),
    
    # Report user paths
    path('report-user/<int:user_id>/', report_user, name='report_user'),
    path('auth/admin/reports/', admin_reports, name='admin_reports'),
    path('auth/admin/handle-report/<int:report_id>/', handle_report, name='handle_report'),
    
    path('auth/admin/manage-user/<int:user_id>/', admin_manage_user, name='admin_manage_user'),
    path('post/<int:post_id>/buy/', buy_post, name='buy_post'),
    path('wallet/add-funds/', add_funds, name='add_funds'),
    path('my-purchases/', my_purchases, name='my_purchases'),

    # Add the new URL patterns for transaction OTP
    
    path('send-transaction-otp/', send_transaction_otp, name='send_transaction_otp'),
    path('verify-transaction-otp/<str:otp_hash>/', verify_transaction_otp, name='verify_transaction_otp'),
]