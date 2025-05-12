from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput,
        help_text='Your password must contain at least 8 characters.'
    )
    password2 = forms.CharField(
        label='Password confirmation',
        widget=forms.PasswordInput,
        help_text='Enter the same password as above, for verification.'
    )

    class Meta:
        model = User
        fields = ("email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data["email"]  # Use email as username
        user.email = self.cleaned_data["email"]
        user.password = make_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        label='Email',
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Enter your email',
            'autofocus': True
        })
    )
    
    password = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Enter your password'
        })
    )

    def clean(self):
        email = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if email and password:
            self.user_cache = authenticate(
                self.request,
                username=email,  # Django will use this as username
                password=password
            )
            if self.user_cache is None:
                raise forms.ValidationError(
                    'Invalid email or password.',
                    code='invalid_login'
                )
        return self.cleaned_data

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True)
    new_password = forms.CharField(widget=forms.PasswordInput, required=True)



from django import forms
from .models import Post

class PostForm(forms.ModelForm):
    """Form for creating marketplace posts"""
    
    class Meta:
        model = Post
        fields = ['title', 'description', 'price', 'image']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Describe your item...'}),
            'title': forms.TextInput(attrs={'placeholder': 'What are you selling?'}),
            'price': forms.NumberInput(attrs={'placeholder': 'Price'})
        }