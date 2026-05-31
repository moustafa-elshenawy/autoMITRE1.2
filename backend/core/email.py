import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

async def send_reset_password_email(email_to: str, reset_url: str):
    smtp_server = os.environ.get("SMTP_SERVER")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_username = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from = os.environ.get("SMTP_FROM_EMAIL", smtp_username)

    if not all([smtp_server, smtp_username, smtp_password]):
        # Fallback to console if SMTP is not fully configured
        print("\n" + "="*50)
        print("      PASSWORD RESET EMAIL TRIGGERED")
        print("="*50)
        print(f"To: {email_to}")
        print("Subject: autoMITRE Password Reset Request")
        print("\nHello,")
        print(f"\nYou requested a password reset. Click the link below to reset your password:")
        print(f"\n{reset_url}")
        print("\nIf you did not request this, please ignore this email.")
        print("="*50 + "\n")
        logger.warning(f"SMTP credentials missing. Fallback console logging for {email_to}")
        return

    try:
        # Construct email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "autoMITRE Password Reset Request"
        msg["From"] = smtp_from
        msg["To"] = email_to

        text = f"""
Hello,

You requested a password reset for your autoMITRE account.
Please click the link below to reset your password:

{reset_url}

If you did not request this password reset, please ignore this email.

Best regards,
The autoMITRE Team
"""
        
        html = f"""
<html>
  <body>
    <p>Hello,</p>
    <p>You requested a password reset for your autoMITRE account.</p>
    <p>Please click the link below to reset your password:</p>
    <p><a href="{reset_url}">{reset_url}</a></p>
    <p>If you did not request this password reset, please ignore this email.</p>
    <br>
    <p>Best regards,<br>The autoMITRE Team</p>
  </body>
</html>
"""
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        msg.attach(part1)
        msg.attach(part2)

        # Send email securely via SMTP
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(smtp_from, email_to, msg.as_string())
            
        logger.info(f"Password reset email successfully sent to {email_to} via SMTP")

    except Exception as e:
        logger.error(f"Failed to send reset email to {email_to}: {e}")
        # Fallback print on failure
        print(f"FAILED TO SEND EMAIL TO {email_to}. Reason: {e}")
        print(f"Reset Link: {reset_url}")
