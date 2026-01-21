const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

// Email templates
const emailTemplates = {
  welcomeEmail: (name, email) => ({
    subject: '🎉 Welcome to SmartKharch!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563EB;">Welcome to SmartKharch! 💰</h1>
        <p>Hi ${name},</p>
        <p>Your account has been successfully created. You're now ready to manage your finances smartly!</p>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3>Get Started:</h3>
          <ul>
            <li>Set your monthly salary</li>
            <li>Create budget categories</li>
            <li>Start tracking your expenses</li>
            <li>Make UPI payments directly from the app</li>
          </ul>
        </div>
        <p>Happy saving! 🚀</p>
        <p>Best regards,<br/>SmartKharch Team</p>
      </div>
    `
  }),

  otpEmail: (otp, name) => ({
    subject: '🔐 Your SmartKharch OTP Code',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563EB;">Your OTP Code</h1>
        <p>Hi ${name},</p>
        <p>Your one-time password (OTP) for SmartKharch is:</p>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
          <h2 style="color: #2563EB; letter-spacing: 5px; margin: 0;">${otp}</h2>
        </div>
        <p style="color: #666;">This code will expire in 5 minutes.</p>
        <p style="color: #999; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
        <p>Best regards,<br/>SmartKharch Team</p>
      </div>
    `
  }),

  transactionReceipt: (userName, amount, merchant, category, date) => ({
    subject: `💳 Payment Receipt - ₹${amount}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563EB;">Payment Receipt</h1>
        <p>Hi ${userName},</p>
        <p>Your payment has been successfully processed!</p>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 10px; color: #666;">Amount:</td>
              <td style="padding: 10px; font-weight: bold; color: #2563EB;">₹${amount}</td>
            </tr>
            <tr>
              <td style="padding: 10px; color: #666;">Merchant:</td>
              <td style="padding: 10px; font-weight: bold;">${merchant}</td>
            </tr>
            <tr>
              <td style="padding: 10px; color: #666;">Category:</td>
              <td style="padding: 10px; font-weight: bold;">${category}</td>
            </tr>
            <tr>
              <td style="padding: 10px; color: #666;">Date & Time:</td>
              <td style="padding: 10px; font-weight: bold;">${date}</td>
            </tr>
          </table>
        </div>
        <p style="color: #666;">Your category balance has been updated accordingly.</p>
        <p>Best regards,<br/>SmartKharch Team</p>
      </div>
    `
  }),

  passwordResetEmail: (resetLink, name) => ({
    subject: '🔑 Reset Your SmartKharch Password',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563EB;">Password Reset Request</h1>
        <p>Hi ${name},</p>
        <p>We received a request to reset your password. Click the button below to proceed:</p>
        <div style="text-align: center; margin: 20px 0;">
          <a href="${resetLink}" style="background-color: #2563EB; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #666;">This link will expire in 1 hour.</p>
        <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email.</p>
        <p>Best regards,<br/>SmartKharch Team</p>
      </div>
    `
  })
};

// Send email function
const sendEmail = async (to, templateName, templateData) => {
  try {
    console.log(`📧 Sending ${templateName} email to ${to}`);
    
    if (!process.env.RESEND_API_KEY) {
      console.log('⚠️ RESEND_API_KEY not set, skipping email in development mode');
      return { success: true, message: 'Email skipped (development mode)' };
    }

    const template = emailTemplates[templateName];
    if (!template) {
      throw new Error(`Email template "${templateName}" not found`);
    }

    const emailContent = template(...templateData);

    const response = await resend.emails.send({
      from: 'SmartKharch <yadavanshika148@gmail.com>',
      to: to,
      subject: emailContent.subject,
      html: emailContent.html
    });

    console.log(`✅ Email sent successfully to ${to}:`, response);
    return { success: true, messageId: response.id };

  } catch (error) {
    console.error(`❌ Failed to send ${templateName} email:`, error);
    return { success: false, error: error.message };
  }
};

// Specific email functions
const sendWelcomeEmail = (email, name) => {
  return sendEmail(email, 'welcomeEmail', [name, email]);
};

const sendOtpEmail = (email, otp, name = 'User') => {
  return sendEmail(email, 'otpEmail', [otp, name]);
};

const sendTransactionReceipt = (email, userName, amount, merchant, category, date) => {
  return sendEmail(email, 'transactionReceipt', [userName, amount, merchant, category, date]);
};

const sendPasswordResetEmail = (email, resetLink, name = 'User') => {
  return sendEmail(email, 'passwordResetEmail', [resetLink, name]);
};

module.exports = {
  sendEmail,
  sendWelcomeEmail,
  sendOtpEmail,
  sendTransactionReceipt,
  sendPasswordResetEmail
};