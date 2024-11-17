const User = require("../models/User");
const bcrypt = require("bcryptjs");
const { sendMail } = require("../utils/Emails");
const { generateOTP } = require("../utils/GenerateOtp");
const Otp = require("../models/OTP");
const { sanitizeUser } = require("../utils/SanitizeUser");
const { generateToken } = require("../utils/GenerateToken");
const PasswordResetToken = require("../models/PasswordResetToken");

// Utility for handling errors
const handleError = (res, error, message, statusCode = 500) => {
  console.error(error);
  res.status(statusCode).json({ message });
};

// Signup
exports.signup = async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    req.body.password = hashedPassword;

    const createdUser = new User(req.body);
    await createdUser.save();

    const secureInfo = sanitizeUser(createdUser);
    const token = generateToken(secureInfo);

    res.cookie("token", token, {
      sameSite: process.env.PRODUCTION === "true" ? "None" : "Lax",
      maxAge: parseInt(process.env.COOKIE_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.PRODUCTION === "true",
    });

    res.status(201).json(sanitizeUser(createdUser));
  } catch (error) {
    handleError(res, error, "Error occurred during signup, please try again later");
  }
};

// Login
exports.login = async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });

    if (existingUser && (await bcrypt.compare(req.body.password, existingUser.password))) {
      const secureInfo = sanitizeUser(existingUser);
      const token = generateToken(secureInfo);

      res.cookie("token", token, {
        sameSite: process.env.PRODUCTION === "true" ? "None" : "Lax",
        maxAge: parseInt(process.env.COOKIE_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.PRODUCTION === "true",
      });

      return res.status(200).json(sanitizeUser(existingUser));
    }

    res.clearCookie("token");
    res.status(404).json({ message: "Invalid Credentials" });
  } catch (error) {
    handleError(res, error, "Error occurred during login, please try again later");
  }
};

// Verify OTP
exports.verifyOtp = async (req, res) => {
  try {
    const user = await User.findById(req.body.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otpRecord = await Otp.findOne({ user: user._id });

    if (!otpRecord) {
      return res.status(404).json({ message: "OTP not found" });
    }

    if (otpRecord.expiresAt < new Date()) {
      await Otp.findByIdAndDelete(otpRecord._id);
      return res.status(400).json({ message: "OTP has expired" });
    }

    if (await bcrypt.compare(req.body.otp, otpRecord.otp)) {
      await Otp.findByIdAndDelete(otpRecord._id);
      const verifiedUser = await User.findByIdAndUpdate(user._id, { isVerified: true }, { new: true });
      return res.status(200).json(sanitizeUser(verifiedUser));
    }

    res.status(400).json({ message: "Invalid OTP" });
  } catch (error) {
    handleError(res, error, "Error occurred while verifying OTP");
  }
};

exports.resendOtp = async (req, res) => {
    try {
        const existingUser = await User.findById(req.body.user);

        if (!existingUser) {
            return res.status(404).json({ message: "User not found" });
        }

        await Otp.deleteMany({ user: existingUser._id });

        const otp = generateOTP();
        const hashedOtp = await bcrypt.hash(otp, 10);

        const newOtp = new Otp({
            user: req.body.user,
            otp: hashedOtp,
            expiresAt: Date.now() + parseInt(process.env.OTP_EXPIRATION_TIME),
        });
        await newOtp.save();

        await sendMail(
            existingUser.email,
            "OTP Verification",
            `Your OTP is: <b>${otp}</b>. Please use it within 5 minutes.`
        );

        res.status(201).json({ message: "OTP sent successfully" });
    } catch (error) {
        console.error("Error in resendOtp:", error);
        res.status(500).json({ message: "Error occurred while resending OTP" });
    }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).json({ message: "Email not found" });
    }

    await PasswordResetToken.deleteMany({ user: user._id });

    const resetToken = generateToken(sanitizeUser(user), true);
    const hashedToken = await bcrypt.hash(resetToken, 10);

    const newToken = new PasswordResetToken({
      user: user._id,
      token: hashedToken,
      expiresAt: Date.now() + parseInt(process.env.OTP_EXPIRATION_TIME),
    });

    await newToken.save();

    await sendMail(
      user.email,
      "Password Reset Link",
      `<p>Reset your password using <a href="${process.env.ORIGIN}/reset-password/${user._id}/${resetToken}">this link</a>. The link is valid for a limited time.</p>`
    );

    res.status(200).json({ message: "Password reset link sent" });
  } catch (error) {
    handleError(res, error, "Error occurred while sending password reset link");
  }
};

// Reset Password
exports.resetPassword = async (req, res) => {
  try {
    const user = await User.findById(req.body.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const tokenRecord = await PasswordResetToken.findOne({ user: user._id });

    if (!tokenRecord || tokenRecord.expiresAt < new Date() || !(await bcrypt.compare(req.body.token, tokenRecord.token))) {
      await PasswordResetToken.findByIdAndDelete(tokenRecord?._id);
      return res.status(400).json({ message: "Invalid or expired reset link" });
    }

    await PasswordResetToken.findByIdAndDelete(tokenRecord._id);

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.findByIdAndUpdate(user._id, { password: hashedPassword });

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    handleError(res, error, "Error occurred while resetting password");
  }
};

// Logout
exports.logout = (req, res) => {
  try {
    res.cookie("token", "", {
      maxAge: 0,
      httpOnly: true,
      secure: process.env.PRODUCTION === "true",
    });
    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    handleError(res, error, "Error occurred while logging out");
  }
};

// Check Auth
exports.checkAuth = async (req, res) => {
  try {
    if (req.user) {
      const user = await User.findById(req.user._id);
      res.status(200).json(sanitizeUser(user));
    } else {
      res.sendStatus(401);
    }
  } catch (error) {
    handleError(res, error, "Error occurred while checking authentication");
  }
};
