const nodemailer = require('nodemailer');

// Check if email credentials are available
const emailConfigured = process.env.EMAIL_USER && process.env.EMAIL_PASS;

// Configure transporter only if credentials exist
let transporter = null;

if (emailConfigured) {
  try {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, // Use Gmail App Password, not your Gmail login password!
      },
    });

    console.log('✅ Email service successfully configured using Gmail.');
  } catch (error) {
    console.error('❌ Failed to configure email service:', error.message);
    transporter = null;
  }
} else {
  console.log('📧 No email credentials found. Running in DEVELOPMENT MODE (emails will not be sent).');
}

/**
 * Send email verification code
 * @param {string} email - recipient email address
 * @param {string} verificationCode - unique code
 */
const sendVerificationEmail = async (email, verificationCode) => {
  console.log(`📧 Preparing to send verification email to: ${email}`);

  // Development mode fallback
  if (!transporter) {
    console.log('⚙️ DEVELOPMENT MODE: No email sent.');
    console.log(`🔑 Use this code manually for testing: ${verificationCode}`);
    return true;
  }

  // Construct email content
  const mailOptions = {
    from: `"Career Platform Lesotho" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify your Email - Career Platform Lesotho',
    html: `
      <div style="font-family: Arial, sans-serif; background: #f9fafb; padding: 20px;">
        <div style="background: white; padding: 30px; border-radius: 8px; max-width: 600px; margin: auto; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
          <h2 style="color: #2c5aa0; text-align: center;">Verify Your Email</h2>
          <p>Hello,</p>
          <p>Thank you for registering with <strong>Career Platform Lesotho</strong>!</p>
          <p>Here’s your email verification code:</p>
          <div style="text-align: center; margin: 25px 0;">
            <span style="font-size: 30px; font-weight: bold; color: #2c5aa0; letter-spacing: 4px;">
              ${verificationCode}
            </span>
          </div>
          <p>Please enter this code on the verification page to activate your account.</p>
          <p style="font-size: 13px; color: #777;">This code expires in 24 hours.</p>
          <br>
          <p>Best regards,<br><strong>Career Platform Team</strong></p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Verification email successfully sent to: ${email}`);
    return true;
  } catch (error) {
    console.error(`⚠️ Failed to send email to ${email}:`, error.message);
    console.log(`🔑 Verification code (use manually): ${verificationCode}`);
    return false;
  }
};

module.exports = {
  sendVerificationEmail,
};
