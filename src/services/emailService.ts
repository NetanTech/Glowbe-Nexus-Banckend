import nodemailer from "nodemailer";

class EmailService {
  private transporter: nodemailer.Transporter | null = null;

  private getTransporter() {
    if (this.transporter) return this.transporter;

    const host = process.env.ZEPTOMAIL_HOST || process.env.SMTP_HOST;
    const user = process.env.ZEPTOMAIL_USER || process.env.SMTP_USER;
    const rawPass =
      process.env.ZEPTOMAIL_API_KEY ||
      process.env.ZEPTOMAIL_PASS ||
      process.env.SMTP_PASS;
    // SMTP wants the bare Send Mail Token. The Zoho-enczapikey prefix is only for the HTTP API.
    const pass = rawPass?.replace(/^Zoho-enczapikey\s+/i, "").trim();
    const port = Number(process.env.ZEPTOMAIL_PORT || process.env.SMTP_PORT || 465);

    if (!host || !user || !pass) {
      return null;
    }

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
      tls: { rejectUnauthorized: false },
    });

    return this.transporter;
  }

  private getFromAddress() {
    const fromName = process.env.EMAIL_FROM_NAME || "Glowbe Nexus";
    const fromEmail =
      process.env.EMAIL_FROM ||
      process.env.EMAIL_FROM_ADDRESS ||
      "noreply@glowbe.nexus";

    return `${fromName} <${fromEmail}>`;
  }

  async sendOtpEmail(to: string, otp: string, purpose: "verify" | "reset") {
    const transporter = this.getTransporter();
    const subject =
      purpose === "verify"
        ? "Verify your Glowbe Nexus account"
        : "Reset your Glowbe Nexus password";
    const text = `Your code is ${otp}. It expires in 10 minutes.`;

    if (!transporter) {
      console.log(`[email:dev] to=${to} purpose=${purpose} otp=${otp}`);
      return { queued: false, preview: true };
    }

    await transporter.sendMail({
      from: this.getFromAddress(),
      to,
      subject,
      text,
    });

    return { queued: true, preview: false };
  }
}

export const emailService = new EmailService();
