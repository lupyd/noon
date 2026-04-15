use anyhow::Result;
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::SmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, Transport};

pub struct Emailer {
    transport: SmtpTransport,
    from_address: Mailbox,
}

impl Emailer {
    pub fn new() -> Result<Self> {
        let smtp_host = std::env::var("SMTP_HOST")?;
        let smtp_username = std::env::var("SMTP_USERNAME")?;
        let smtp_password = std::env::var("SMTP_PASSWORD")?;
        let from_address = std::env::var("SMTP_FROM")?;

        let credentials = Credentials::new(smtp_username, smtp_password);
        let transport = SmtpTransport::starttls_relay(&smtp_host)?
            .credentials(credentials)
            .build();

        let from_address = from_address.parse()?;

        Ok(Self {
            transport,
            from_address,
        })
    }

    pub fn send_otp_email(&self, to_email: &str, form_name: &str, otp: &str) -> Result<()> {
        let to_address: Mailbox = to_email.parse()?;

        let text_body = format!(
            "Your one-time password for form '{}' is: {}\n\nThis code expires in 5 minutes.",
            form_name, otp
        );

        let html_content = format!(
            r#"<h1>Security Code</h1>
            <p>Your one-time password for <strong>{}</strong> is below. Use it to verify your access.</p>
            <div class="otp-container">
                <div class="otp">{}</div>
            </div>
            <p>This code will expire in 5 minutes for your security.</p>"#,
            form_name, otp
        );

        let html_body = self.wrap_html(&html_content);

        let email = Message::builder()
            .from(self.from_address.clone())
            .to(to_address)
            .subject(format!("Your OTP for {}", form_name))
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text_body))
                    .singlepart(SinglePart::html(html_body)),
            )?;

        self.transport.send(&email)?;
        log::info!("OTP email sent to {}", to_email);
        Ok(())
    }

    pub fn send_form_invitation(
        &self,
        to_email: &str,
        form_name: &str,
        owner_name: &str,
        form_link: &str,
    ) -> Result<()> {
        let to_address: Mailbox = to_email.parse()?;

        let text_body = format!(
            "Hello,\n\n{} has invited you to fill out the form: {}\n\nYou can access it directly using the following link:\n{}\n\nThank you!",
            owner_name, form_name, form_link
        );

        let html_content = format!(
            r#"<h1>Form Invitation</h1>
            <p><strong>{}</strong> has invited you to fill out the form <strong>{}</strong>.</p>
            <p>You can access the form directly by clicking the button below:</p>
            <div class="button-container">
                <a href="{}" class="button">Open Form</a>
            </div>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="font-size: 12px; word-break: break-all;"><a href="{}" class="link" style="color: #6d28d9;">{}</a></p>"#,
            owner_name, form_name, form_link, form_link, form_link
        );

        let html_body = self.wrap_html(&html_content);

        let email = Message::builder()
            .from(self.from_address.clone())
            .to(to_address)
            .subject(format!("Invitation to fill {}", form_name))
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text_body))
                    .singlepart(SinglePart::html(html_body)),
            )?;

        self.transport.send(&email)?;
        log::info!("Invitation email sent to {}", to_email);
        Ok(())
    }

    fn wrap_html(&self, content: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #334155; margin: 0; padding: 0; width: 100% !important; }}
        .wrapper {{ background-color: #f8fafc; padding: 40px 20px; }}
        .content {{ background-color: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; margin: 0 auto; max-width: 500px; padding: 40px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }}
        h1 {{ color: #0f172a; font-size: 20px; font-weight: 700; margin-top: 0; margin-bottom: 24px; text-align: left; }}
        p {{ color: #475569; font-size: 16px; line-height: 1.6; text-align: left; margin: 0 0 16px; }}
        .otp-container {{ background-color: #f1f5f9; border-radius: 8px; padding: 24px; text-align: center; margin: 24px 0; }}
        .otp {{ color: #6d28d9; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 32px; font-weight: 800; letter-spacing: 0.25em; }}
        .button-container {{ margin: 32px 0; }}
        .button {{ background-color: #0f172a; border-radius: 6px; color: #ffffff !important; display: inline-block; font-size: 15px; font-weight: 600; padding: 12px 24px; text-decoration: none; text-align: center; }}
        .footer {{ color: #94a3b8; font-size: 13px; margin-top: 40px; text-align: center; }}
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="content">
            {}
            <div class="footer">
                &copy; 2026 Noon. Deeply private forms.
            </div>
        </div>
    </div>
</body>
</html>"#,
            content
        )
    }
}

impl Default for Emailer {
    fn default() -> Self {
        Self::new().expect("Failed to create emailer - check SMTP env vars")
    }
}
