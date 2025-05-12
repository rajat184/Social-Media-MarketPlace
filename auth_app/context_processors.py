def admin_context(request):
    context = {}
    if request.user.is_authenticated and request.user.is_staff:
        try:
            from django.apps import apps
            UserDocument = apps.get_model('auth_app', 'UserDocument')
            context['pending_documents_count'] = UserDocument.objects.filter(status='pending').count()
        except Exception as e:
            print(f"Error in admin_context: {e}")
            context['pending_documents_count'] = 0
    return context

def unread_messages_count(request):
    if request.user.is_authenticated:
        try:
            from django.apps import apps
            Message = apps.get_model('auth_app', 'Message')
            count = Message.objects.filter(receiver=request.user, is_read=False).count()
            return {'unread_messages_count': count}
        except Exception as e:
            print(f"Error in unread_messages_count: {e}")
    return {'unread_messages_count': 0}