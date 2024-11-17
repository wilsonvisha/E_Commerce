require("dotenv").config();
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // true for 465, false for 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.error("SMTP connection failed:", error);
  } else {
    console.log("SMTP connection successful!");
  }
});
const sendMail = async (to, subject, html) => {
  const mailOptions = {
      from: process.env.EMAIL,
      to,
      subject,
      html,
  };
  await transporter.sendMail(mailOptions);
};

module.exports = { sendMail };