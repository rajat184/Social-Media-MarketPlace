# 🛍️ Social Media Marketplace

A full-stack social media marketplace web application where users can register, create profiles, interact, and securely buy/sell products — combining the features of a social platform with e-commerce functionality.

---

## 📌 Features

### 👤 User Features
- Register and login with secure authentication
- Create and update user profile
- Chat/messaging system (prototype)
- Post products for sale
- Browse and search products
- Add to wishlist/cart

### 🛡️ Admin Features
- Admin dashboard for managing users and listings
- User access control and moderation tools

### 🔐 Security
- User data protected with hashed passwords
- Input validation and basic security measures in place
- Configured with end-to-end security on Ubuntu using NGINX, PostgreSQL, and secure login workflows

---

## 🛠️ Tech Stack

| Layer      | Technology                         |
|------------|-------------------------------------|
| Frontend   | React.js, HTML, CSS, JavaScript     |
| Backend    | Django, Python                      |
| Database   | PostgreSQL                          |
| Web Server | NGINX                               |
| OS/Host    | Ubuntu                              |

---

## 🚀 How to Run Locally

1. **Clone the repository**
```bash
git clone https://github.com/rajat184/Social-Media-MarketPlace.git
cd Social-Media-MarketPlace
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
