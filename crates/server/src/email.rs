use anyhow::Result;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::SmtpTransport;
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

        let email = Message::builder()
            .from(self.from_address.clone())
            .to(to_address)
            .subject(format!("Your OTP for {}", form_name))
            .body(format!(
                "Your one-time password for form '{}' is: {}\n\nThis code expires in 5 minutes.",
                form_name, otp
            ))?;

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

        let email = Message::builder()
            .from(self.from_address.clone())
            .to(to_address)
            .subject(format!("Invitation to fill {}", form_name))
            .body(format!(
                "Hello,\n\n{} has invited you to fill out the form: {}\n\nYou can access it directly using the following link:\n{}\n\nThank you!",
                owner_name, form_name, form_link
            ))?;

        self.transport.send(&email)?;
        log::info!("Invitation email sent to {}", to_email);
        Ok(())
    }
}

impl Default for Emailer {
    fn default() -> Self {
        Self::new().expect("Failed to create emailer - check SMTP env vars")
    }
}
