"""
Email utilities for the application.
This module handles all email related functionality using Mailjet API.
"""

import os
import string
import secrets
from datetime import datetime
from mailjet_rest import Client
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

# Email configuration
EMAIL_CONFIG = {
    'API_KEY': os.environ.get('MAILJET_API_KEY'),
    'API_SECRET': os.environ.get('MAILJET_API_SECRET'),
    'FROM_EMAIL': os.environ.get('FROM_EMAIL', 'noreply@examportal.com'),
    'FROM_NAME': 'ExamPortal System',
    'RESET_PASSWORD_URL': os.environ.get('RESET_PASSWORD_URL')
}

def generate_username(full_name, existing_usernames):
    """
    Generate a unique username based on full name.
    
    Args:
        full_name (str): User's full name
        existing_usernames (list): List of existing usernames to avoid duplicates
        
    Returns:
        str: A unique username
    """
    name_parts = full_name.lower().replace(' ', '').replace('.', '')
    base_username = name_parts[:8]

    username = base_username
    counter = 1
    while username in existing_usernames:
        username = f"{base_username}{counter}"
        counter += 1

    return username

def generate_password(length=8):
    """
    Generate a random password.
    
    Args:
        length (int): Length of the password
        
    Returns:
        str: A random password
    """
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

# REPLACE send_credentials_email() with these two functions:

# REPLACE BOTH FUNCTIONS IN email_utils.py WITH THESE UPDATED VERSIONS:

def send_password_setup_email(email, full_name, username, token):
    """
    Send account setup email with secure token link and username info.
    """
    try:
        if not EMAIL_CONFIG['API_KEY'] or not EMAIL_CONFIG['API_SECRET']:
            raise ValueError("Mailjet API credentials are not configured")
            
        # Get setup URL from environment variable or construct it
        base_url = os.environ.get('BASE_URL', 'https://your-domain.com')
        setup_url = f"{base_url}/setup-password/{token}"
            
        # Use Mailjet API
        mailjet = Client(auth=(EMAIL_CONFIG['API_KEY'], EMAIL_CONFIG['API_SECRET']), version='v3.1')
        
        # Create HTML content with username information
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to ExamPortal - Set Up Your Account</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 0;
                }}
                .container {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 0;
                    margin: 0;
                }}
                .email-wrapper {{
                    background: white;
                    margin: 20px;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 700;
                }}
                .content {{
                    padding: 40px 30px;
                }}
                .credentials-box {{
                    background: #f8f9ff;
                    border: 2px solid #e5e7eb;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: center;
                }}
                .credential-item {{
                    margin: 10px 0;
                    padding: 8px;
                    background: white;
                    border-radius: 6px;
                    border-left: 4px solid #667eea;
                }}
                .credential-label {{
                    font-weight: 600;
                    color: #4b5563;
                    font-size: 14px;
                }}
                .credential-value {{
                    font-family: 'Monaco', 'Courier New', monospace;
                    font-size: 16px;
                    color: #1f2937;
                    font-weight: 600;
                    margin-top: 4px;
                }}
                .setup-button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                    color: white;
                    padding: 15px 35px;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                    font-size: 16px;
                    margin: 20px 0;
                    box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
                }}
                .security-note {{
                    background: #ecfdf5;
                    border-left: 4px solid #10b981;
                    padding: 15px;
                    border-radius: 6px;
                    margin: 20px 0;
                }}
                .footer {{
                    background: #f9fafb;
                    padding: 20px;
                    text-align: center;
                    color: #6b7280;
                    font-size: 14px;
                }}
                ul {{
                    text-align: left;
                    padding-left: 20px;
                }}
                li {{
                    margin: 8px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="email-wrapper">
                    <div class="header">
                        <h1>Welcome to ExamPortal!</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Your account has been created successfully</p>
                    </div>
                    
                    <div class="content">
                        <h2 style="color: #1f2937; margin-top: 0;">Hello {full_name}!</h2>
                        
                        <p>Thank you for joining ExamPortal. Your account has been created and here are your login credentials:</p>
                        
                        <div class="credentials-box">
                            <h3 style="margin-top: 0; color: #374151;">Your Login Credentials</h3>
                            
                            <div class="credential-item">
                                <div class="credential-label">Email Address</div>
                                <div class="credential-value">{email}</div>
                            </div>
                            
                            <div class="credential-item">
                                <div class="credential-label">Username</div>
                                <div class="credential-value">{username}</div>
                            </div>
                            
                            <p style="margin-top: 15px; color: #6b7280; font-size: 14px;">
                                <strong>Note:</strong> You can login using either your email address or username
                            </p>
                        </div>

                        <p>To complete your registration and secure your account, please set up your password using the secure link below:</p>

                        <div style="text-align: center;">
                            <a href="{setup_url}" class="setup-button">Set Up Your Password</a>
                        </div>
                        
                        <p><strong>Important Security Information:</strong></p>
                        <ul>
                            <li>This setup link will expire in <strong>1 hour</strong> for security</li>
                            <li>You can only use this link once</li>
                            <li>Choose a strong password with at least 10 characters</li>
                            <li>Include uppercase, lowercase, numbers, and special characters</li>
                            <li>If the link expires, please contact admin for a new one</li>
                        </ul>
                        
                        <div class="security-note">
                            <h3 style="color: #047857; margin-top: 0;">Security Notice</h3>
                            <p style="color: #065f46; margin-bottom: 0;">
                                For your security, we never send passwords via email. This secure setup process ensures only you can access your account.
                            </p>
                        </div>

                        <p>If you have any questions or need assistance, please contact our support team.</p>

                        <p>Best regards,<br><strong>The ExamPortal Team</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p><strong>ExamPortal System</strong></p>
                        <p>Setup link sent on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                        <p>This link expires in 1 hour for security.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

        # Create plain text content as fallback
        text_content = f"""
        Welcome to ExamPortal!

        Dear {full_name},

        Thank you for creating an account with ExamPortal. Your account has been created successfully!

        YOUR LOGIN CREDENTIALS:
        Email: {email}
        Username: {username}
        Note: You can login using either your email address or username

        To complete your registration, please set up your password using this secure link:
        {setup_url}

        IMPORTANT SECURITY INFORMATION:
        - This setup link expires in 1 hour for security
        - You can only use this link once
        - Choose a strong password with at least 10 characters
        - Include uppercase, lowercase, numbers, and special characters
        - If the link expires, please contact admin for assistance

        SECURITY NOTICE:
        For your security, we never send passwords via email. This secure setup process ensures only you can access your account.

        If you have any questions, please contact our support team.

        Best regards,
        The ExamPortal Team

        Setup link sent on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
        This link expires in 1 hour for security.
        """

        # Prepare email data for Mailjet API
        data = {
            'Messages': [
                {
                    'From': {
                        'Email': EMAIL_CONFIG['FROM_EMAIL'],
                        'Name': EMAIL_CONFIG['FROM_NAME']
                    },
                    'To': [
                        {
                            'Email': email,
                            'Name': full_name
                        }
                    ],
                    'Subject': 'Welcome to ExamPortal - Complete Your Account Setup',
                    'TextPart': text_content,
                    'HTMLPart': html_content
                }
            ]
        }

        # Send email using Mailjet
        result = mailjet.send.create(data=data)
        
        if result.status_code == 200:
            print(f"Setup email successfully sent to {email} with username: {username}")
            return True, "Setup email sent successfully"
        else:
            print(f"Mailjet error: {result.json()}")
            return False, f"Failed to send setup email: API returned status {result.status_code}"

    except Exception as e:
        print(f"Error sending setup email: {e}")
        import traceback
        traceback.print_exc()
        return False, f"Failed to send setup email: {str(e)}"


def send_password_reset_email(email, full_name, username, token):
    """
    Send password reset email with secure token link and username reminder.
    """
    try:
        if not EMAIL_CONFIG['API_KEY'] or not EMAIL_CONFIG['API_SECRET']:
            raise ValueError("Mailjet API credentials are not configured")
            
        # Get reset URL from environment variable or construct it  
        base_url = os.environ.get('BASE_URL', 'https://your-domain.com')
        reset_url = f"{base_url}/reset-password/{token}"
            
        # Use Mailjet API
        mailjet = Client(auth=(EMAIL_CONFIG['API_KEY'], EMAIL_CONFIG['API_SECRET']), version='v3.1')
        
        # Create HTML content with username information
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your ExamPortal Password</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 0;
                }}
                .container {{
                    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                    padding: 0;
                    margin: 0;
                }}
                .email-wrapper {{
                    background: white;
                    margin: 20px;
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 700;
                }}
                .content {{
                    padding: 40px 30px;
                }}
                .credentials-box {{
                    background: #fff7ed;
                    border: 2px solid #fed7aa;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                    text-align: center;
                }}
                .credential-item {{
                    margin: 10px 0;
                    padding: 8px;
                    background: white;
                    border-radius: 6px;
                    border-left: 4px solid #f59e0b;
                }}
                .credential-label {{
                    font-weight: 600;
                    color: #4b5563;
                    font-size: 14px;
                }}
                .credential-value {{
                    font-family: 'Monaco', 'Courier New', monospace;
                    font-size: 16px;
                    color: #1f2937;
                    font-weight: 600;
                    margin-top: 4px;
                }}
                .reset-button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
                    color: white;
                    padding: 15px 35px;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                    font-size: 16px;
                    margin: 20px 0;
                    box-shadow: 0 4px 15px rgba(220, 38, 38, 0.3);
                }}
                .security-note {{
                    background: #fef3c7;
                    border-left: 4px solid #f59e0b;
                    padding: 15px;
                    border-radius: 6px;
                    margin: 20px 0;
                }}
                .footer {{
                    background: #f9fafb;
                    padding: 20px;
                    text-align: center;
                    color: #6b7280;
                    font-size: 14px;
                }}
                ul {{
                    text-align: left;
                    padding-left: 20px;
                }}
                li {{
                    margin: 8px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="email-wrapper">
                    <div class="header">
                        <h1>Password Reset Request</h1>
                        <p style="margin: 10px 0 0 0; opacity: 0.9;">Reset your ExamPortal password</p>
                    </div>
                    
                    <div class="content">
                        <h2 style="color: #1f2937; margin-top: 0;">Hello {full_name}!</h2>
                        
                        <p>We received a request to reset the password for your ExamPortal account. Here are your account details:</p>
                        
                        <div class="credentials-box">
                            <h3 style="margin-top: 0; color: #374151;">Your Account Information</h3>
                            
                            <div class="credential-item">
                                <div class="credential-label">Email Address</div>
                                <div class="credential-value">{email}</div>
                            </div>
                            
                            <div class="credential-item">
                                <div class="credential-label">Username</div>
                                <div class="credential-value">{username}</div>
                            </div>
                            
                            <p style="margin-top: 15px; color: #6b7280; font-size: 14px;">
                                <strong>Remember:</strong> You can login using either your email address or username
                            </p>
                        </div>

                        <p>If you requested this password reset, click the button below to choose a new password:</p>

                        <div style="text-align: center;">
                            <a href="{reset_url}" class="reset-button">Reset Your Password</a>
                        </div>
                        
                        <p><strong>Security Information:</strong></p>
                        <ul>
                            <li>This reset link will expire in <strong>1 hour</strong> for security</li>
                            <li>You can only use this link once</li>
                            <li>Choose a strong password with at least 10 characters</li>
                            <li>If you didn't request this reset, you can safely ignore this email</li>
                            <li>Your account remains secure and no changes have been made</li>
                        </ul>
                        
                        <div class="security-note">
                            <h3 style="color: #b45309; margin-top: 0;">Security Notice</h3>
                            <p style="color: #b45309; margin-bottom: 0;">
                                If you didn't request this password reset, please contact our support team immediately. Never share this link with anyone.
                            </p>
                        </div>

                        <p>If you have any questions or need assistance, please contact our support team.</p>

                        <p>Best regards,<br><strong>The ExamPortal Team</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p><strong>ExamPortal System</strong></p>
                        <p>Reset link sent on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                        <p>This link expires in 1 hour for security.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

        # Create plain text content as fallback
        text_content = f"""
        Password Reset Request - ExamPortal

        Dear {full_name},

        We received a request to reset the password for your ExamPortal account.

        YOUR ACCOUNT INFORMATION:
        Email: {email}
        Username: {username}
        Remember: You can login using either your email address or username

        If you requested this password reset, use this secure link to choose a new password:
        {reset_url}

        SECURITY INFORMATION:
        - This reset link expires in 1 hour for security
        - You can only use this link once
        - Choose a strong password with at least 10 characters
        - If you didn't request this reset, you can safely ignore this email
        - Your account remains secure and no changes have been made

        SECURITY NOTICE:
        If you didn't request this password reset, please contact our support team immediately. Never share this link with anyone.

        If you have any questions, please contact our support team.

        Best regards,
        The ExamPortal Team

        Reset link sent on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
        This link expires in 1 hour for security.
        """

        # Prepare email data for Mailjet API
        data = {
            'Messages': [
                {
                    'From': {
                        'Email': EMAIL_CONFIG['FROM_EMAIL'],
                        'Name': EMAIL_CONFIG['FROM_NAME']
                    },
                    'To': [
                        {
                            'Email': email,
                            'Name': full_name
                        }
                    ],
                    'Subject': 'Reset Your ExamPortal Password',
                    'TextPart': text_content,
                    'HTMLPart': html_content
                }
            ]
        }

        # Send email using Mailjet
        result = mailjet.send.create(data=data)
        
        if result.status_code == 200:
            print(f"Reset email successfully sent to {email} with username: {username}")
            return True, "Reset email sent successfully"
        else:
            print(f"Mailjet error: {result.json()}")
            return False, f"Failed to send reset email: API returned status {result.status_code}"

    except Exception as e:
        print(f"Error sending reset email: {e}")
        import traceback
        traceback.print_exc()
        return False, f"Failed to send reset email: {str(e)}"