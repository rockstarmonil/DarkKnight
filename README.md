# 🦇 DarkKnight – Secure SSO Application

**DarkKnight** is a Spring Boot–based authentication and identity management application integrating **miniOrange as IdP** to enable **SSO (Single Sign-On)** via **JWT** and **SAML**.  
It features **multi-role dashboards** (Main Admin, Admin, and User), CRUD management for users/admins, and a futuristic **neon-inspired UI**.

---

## 🚀 Features

### 🔐 Authentication & SSO
- **JWT-based Single Sign-On (SSO)** integrated with **miniOrange IdP**
- Supports both **SAML 2.0** and **JWT** for flexibility
- Secure **session handling** and **user role-based access**

### 👥 Role-Based Dashboards
- **Main Admin Dashboard** – manage all admins and users  
- **Admin Dashboard** – manage users within assigned subdomain  
- **User Dashboard** – view personal information and account details  

### ⚙️ Admin Features
- Create, edit, and delete **Admin** or **User** accounts  
- Create **subdomains** for organizations/companies  
- Assign roles and manage user status (Active/Inactive)  
- View system metrics (total users, admins, uptime)

### 🧱 Tech Stack
| Layer | Technology |
|-------|-------------|
| Backend | Java 17, Spring Boot 3.x |
| Frontend | Thymeleaf, Bootstrap 5 |
| Security | Spring Security, JWT, miniOrange SAML |
| Database | MySQL / PostgreSQL (configurable via `application.properties`) |
| Deployment | Render / AWS / Localhost |
| Build Tool | Maven |

---



