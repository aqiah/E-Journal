Luxe Journal Studio
A sophisticated, secure personal journal application built with Flask. This project focuses on providing a customizable writing experience while maintaining high standards of web security.

Features
Dynamic Themes: Toggle between various aesthetic modes including Classic, Rosewood, and Caturday.

Secure Auth: Industry-standard password hashing and session management.

Photo Journaling: Securely attach images to your memories.

Responsive Design: A beautiful, dark-mode focused UI for seamless journaling.

Security Core
Access Control: Implements Role-Based Access Control (RBAC) to protect sensitive routes.

Brute-Force Protection: Rate limiting on authentication endpoints.

Environment Safety: Sensitive credentials managed via environment variables.

File Sanitization: Strict validation and sanitization of user-uploaded content.

Quick Start
Clone the repository.

Install dependencies: pip install -r requirements.txt.

Set up your .env file with a SECRET_KEY.

Run python haiqa.py.