import express, { Request, Response } from "express";
import { query, queryOne } from "../config/database";
import {
  hashPassword,
  comparePassword,
  generateAccessToken,
  generateRefreshToken,
  generateTemporaryToken,
  generateSecureOTP,
  validateEmail,
  validatePassword,
  verifyToken,
  OTP_CONFIG,
} from "../utils/auth";
import { authenticateToken, AuthRequest } from "../middleware/auth";
import { authLimiter, authStrictLimiter } from "../middleware/rateLimit";
import { emailService } from "../services/emailService";

const router = express.Router();

const PUBLIC_USER_FIELDS =
  "user_id, name, email, role, phone_number, email_verified, account_status, created_at, updated_at";

type PublicUser = {
  user_id: string;
  name: string;
  email: string;
  role: string;
  phone_number: string | null;
  email_verified: boolean;
  account_status: string;
  created_at: string;
  updated_at: string;
};

type AuthUser = PublicUser & {
  password: string | null;
  token_version: number;
  email_otp: string | null;
  email_otp_expires_at: string | Date | null;
  reset_otp: string | null;
  reset_otp_expires_at: string | Date | null;
};

router.use(["/login", "/register", "/refresh"], authLimiter);
router.use(
  [
    "/forgot-password",
    "/reset-password",
    "/verify-email",
    "/resend-verification",
    "/resend-reset-code",
  ],
  authStrictLimiter
);

function hasLocalPassword(user: { password?: string | null }): boolean {
  return typeof user.password === "string" && user.password.trim().length > 0;
}

function expired(value: string | Date | null | undefined) {
  if (!value) return false;
  return new Date(value).getTime() < Date.now();
}

async function sendCode(email: string, otp: string, purpose: "verify" | "reset") {
  try {
    const result = await emailService.sendOtpEmail(email, otp, purpose);
    if (result.preview && process.env.NODE_ENV !== "production") {
      console.log(`[email:dev] to=${email} purpose=${purpose} otp=${otp}`);
    }
  } catch (error) {
    console.error("OTP email failed:", error);
    if (process.env.NODE_ENV !== "production") {
      console.log(`[email:dev] to=${email} purpose=${purpose} otp=${otp}`);
    }
  }
}

// ============================================================
// REGISTER
// ============================================================
router.post("/register", async (req: Request, res: Response) => {
  try {
    const { name, email: rawEmail, password, phone_number } = req.body;
    const email =
      typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";

    if (!name || !email || !password) {
      res.status(400).json({
        success: false,
        message: "Name, email and password are required",
      });
      return;
    }

    if (!validateEmail(email)) {
      res.status(400).json({ success: false, message: "Invalid email address" });
      return;
    }

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.isValid) {
      res.status(400).json({ success: false, message: passwordCheck.message });
      return;
    }

    const existingUser = await queryOne<{ user_id: string }>(
      "select user_id from users where email = $1",
      [email]
    );

    if (existingUser) {
      res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
      return;
    }

    const hashedPassword = await hashPassword(password);
    const otp = generateSecureOTP();
    const otpExpiresAt = new Date(Date.now() + OTP_CONFIG.expiresIn * 1000);

    const newUser = await queryOne<PublicUser>(
      `insert into users (
        name, email, password, phone_number, role, email_verified,
        account_status, email_otp, email_otp_expires_at, token_version
      ) values ($1, $2, $3, $4, 'user', false, 'pending', $5, $6, 0)
      returning ${PUBLIC_USER_FIELDS}`,
      [
        String(name).trim(),
        email,
        hashedPassword,
        phone_number || null,
        otp,
        otpExpiresAt,
      ]
    );

    if (!newUser) {
      res.status(500).json({
        success: false,
        message: "Failed to create user account",
      });
      return;
    }

    await sendCode(email, otp, "verify");

    const tempToken = generateTemporaryToken(newUser.user_id, email);

    res.status(201).json({
      success: true,
      message: "Account created. Please verify your email.",
      data: {
        user: newUser,
        email,
        temporaryToken: tempToken,
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

// ============================================================
// LOGIN
// ============================================================
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email: rawEmail, password } = req.body;
    const email =
      typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";

    if (!email || !password) {
      res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
      return;
    }

    const user = await queryOne<AuthUser>(
      `select ${PUBLIC_USER_FIELDS}, password, token_version
       from users where email = $1`,
      [email]
    );

    if (!user || !hasLocalPassword(user) || !user.password) {
      res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
      return;
    }

    const valid = await comparePassword(password, user.password);
    if (!valid) {
      res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
      return;
    }

    if (user.account_status === "suspended" || user.account_status === "banned") {
      res.status(403).json({
        success: false,
        message: "Account is not allowed to sign in",
      });
      return;
    }

    if (!user.email_verified) {
      const otp = generateSecureOTP();
      const otpExpiresAt = new Date(Date.now() + OTP_CONFIG.expiresIn * 1000);

      await query(
        `update users
         set email_otp = $1, email_otp_expires_at = $2, updated_at = now()
         where user_id = $3`,
        [otp, otpExpiresAt, user.user_id]
      );

      await sendCode(email, otp, "verify");

      const temporaryToken = generateTemporaryToken(user.user_id, email);

      res.status(403).json({
        success: false,
        message: "Please verify your email to continue",
        data: {
          verification_required: true,
          email,
          temporaryToken,
        },
      });
      return;
    }

    const tokenVersion = user.token_version || 0;
    const accessToken = generateAccessToken(user.user_id, user.email, tokenVersion);
    const refreshToken = generateRefreshToken(user.user_id, tokenVersion);

    const { password: _pw, token_version: _tv, ...safeUser } = user;

    res.json({
      success: true,
      message: "Logged in successfully",
      data: {
        user: safeUser,
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

// ============================================================
// VERIFY EMAIL
// ============================================================
router.post("/verify-email", async (req: Request, res: Response) => {
  try {
    const { email: rawEmail, otp, code } = req.body;
    const email =
      typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";
    const submitted = String(otp || code || "").trim();

    if (!email || !submitted) {
      res.status(400).json({
        success: false,
        message: "Email and verification code are required",
      });
      return;
    }

    const user = await queryOne<AuthUser>(
      `select user_id, email, email_otp, email_otp_expires_at, email_verified, token_version
       from users where email = $1`,
      [email]
    );

    if (!user) {
      res.status(404).json({ success: false, message: "User not found" });
      return;
    }

    if (user.email_verified) {
      res.json({
        success: true,
        message: "Email already verified",
      });
      return;
    }

    if (!user.email_otp || user.email_otp !== submitted) {
      res.status(400).json({ success: false, message: "Invalid verification code" });
      return;
    }

    if (expired(user.email_otp_expires_at)) {
      res.status(400).json({ success: false, message: "Verification code expired" });
      return;
    }

    const updated = await queryOne<PublicUser>(
      `update users
       set email_verified = true,
           account_status = 'active',
           email_otp = null,
           email_otp_expires_at = null,
           updated_at = now()
       where user_id = $1
       returning ${PUBLIC_USER_FIELDS}`,
      [user.user_id]
    );

    if (!updated) {
      res.status(500).json({ success: false, message: "Failed to verify email" });
      return;
    }

    const tokenVersion = user.token_version || 0;
    const accessToken = generateAccessToken(user.user_id, user.email, tokenVersion);
    const refreshToken = generateRefreshToken(user.user_id, tokenVersion);

    res.json({
      success: true,
      message: "Email verified successfully",
      data: {
        user: updated,
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("Verify email error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

// ============================================================
// RESEND VERIFICATION
// ============================================================
router.post("/resend-verification", async (req: Request, res: Response) => {
  try {
    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    if (!email) {
      res.status(400).json({ success: false, message: "Email is required" });
      return;
    }

    const user = await queryOne<{
      user_id: string;
      email_verified: boolean;
    }>(
      "select user_id, email_verified from users where email = $1",
      [email]
    );

    if (!user) {
      res.json({
        success: true,
        message: "If an account exists, a code has been sent",
      });
      return;
    }

    if (user.email_verified) {
      res.json({ success: true, message: "Email already verified" });
      return;
    }

    const otp = generateSecureOTP();
    const otpExpiresAt = new Date(Date.now() + OTP_CONFIG.expiresIn * 1000);

    await query(
      `update users
       set email_otp = $1, email_otp_expires_at = $2, updated_at = now()
       where user_id = $3`,
      [otp, otpExpiresAt, user.user_id]
    );

    await sendCode(email, otp, "verify");

    res.json({
      success: true,
      message: "Verification code sent",
    });
  } catch (error) {
    console.error("Resend verification error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

// ============================================================
// FORGOT PASSWORD
// ============================================================
router.post("/forgot-password", async (req: Request, res: Response) => {
  try {
    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    if (!email) {
      res.status(400).json({ success: false, message: "Email is required" });
      return;
    }

    const user = await queryOne<{ user_id: string }>(
      "select user_id from users where email = $1",
      [email]
    );

    if (user) {
      const otp = generateSecureOTP();
      const otpExpiresAt = new Date(Date.now() + OTP_CONFIG.expiresIn * 1000);

      await query(
        `update users
         set reset_otp = $1, reset_otp_expires_at = $2, updated_at = now()
         where user_id = $3`,
        [otp, otpExpiresAt, user.user_id]
      );

      await sendCode(email, otp, "reset");
    }

    res.json({
      success: true,
      message: "If an account exists, a reset code has been sent",
      data: { email },
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

router.post("/resend-reset-code", async (req: Request, res: Response) => {
  try {
    const email =
      typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";

    if (!email) {
      res.status(400).json({ success: false, message: "Email is required" });
      return;
    }

    const user = await queryOne<{ user_id: string }>(
      "select user_id from users where email = $1",
      [email]
    );

    if (user) {
      const otp = generateSecureOTP();
      const otpExpiresAt = new Date(Date.now() + OTP_CONFIG.expiresIn * 1000);
      await query(
        `update users
         set reset_otp = $1, reset_otp_expires_at = $2, updated_at = now()
         where user_id = $3`,
        [otp, otpExpiresAt, user.user_id]
      );
      await sendCode(email, otp, "reset");
    }

    res.json({
      success: true,
      message: "If an account exists, a reset code has been sent",
    });
  } catch (error) {
    console.error("Resend reset code error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

// ============================================================
// RESET PASSWORD
// ============================================================
router.post("/reset-password", async (req: Request, res: Response) => {
  try {
    const { email: rawEmail, otp, code, password } = req.body;
    const email =
      typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";
    const submitted = String(otp || code || "").trim();

    if (!email || !submitted || !password) {
      res.status(400).json({
        success: false,
        message: "Email, code and new password are required",
      });
      return;
    }

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.isValid) {
      res.status(400).json({ success: false, message: passwordCheck.message });
      return;
    }

    const user = await queryOne<{
      user_id: string;
      reset_otp: string | null;
      reset_otp_expires_at: string | Date | null;
      token_version: number | null;
    }>(
      `select user_id, reset_otp, reset_otp_expires_at, token_version
       from users where email = $1`,
      [email]
    );

    if (!user || !user.reset_otp || user.reset_otp !== submitted) {
      res.status(400).json({ success: false, message: "Invalid reset code" });
      return;
    }

    if (expired(user.reset_otp_expires_at)) {
      res.status(400).json({ success: false, message: "Reset code expired" });
      return;
    }

    const hashedPassword = await hashPassword(password);
    const nextVersion = (user.token_version || 0) + 1;

    await query(
      `update users
       set password = $1,
           reset_otp = null,
           reset_otp_expires_at = null,
           token_version = $2,
           updated_at = now()
       where user_id = $3`,
      [hashedPassword, nextVersion, user.user_id]
    );

    res.json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

// ============================================================
// REFRESH
// ============================================================
router.post("/refresh", async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400).json({ success: false, message: "Refresh token required" });
      return;
    }

    const decoded = verifyToken(refreshToken) as {
      userId: string;
      type?: string;
      tv?: number;
    };

    if (decoded.type !== "refresh") {
      res.status(401).json({ success: false, message: "Invalid refresh token" });
      return;
    }

    const user = await queryOne<{
      user_id: string;
      email: string;
      token_version: number | null;
    }>(
      "select user_id, email, token_version from users where user_id = $1",
      [decoded.userId]
    );

    if (!user) {
      res.status(401).json({ success: false, message: "User not found" });
      return;
    }

    if ((decoded.tv || 0) !== (user.token_version || 0)) {
      res.status(401).json({ success: false, message: "Session expired" });
      return;
    }

    const accessToken = generateAccessToken(
      user.user_id,
      user.email,
      user.token_version || 0
    );

    res.json({
      success: true,
      data: { accessToken },
    });
  } catch {
    res.status(401).json({ success: false, message: "Invalid refresh token" });
  }
});

// ============================================================
// ME
// ============================================================
router.get("/me", authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const user = await queryOne<PublicUser>(
      `select ${PUBLIC_USER_FIELDS} from users where user_id = $1`,
      [req.user!.id]
    );

    if (!user) {
      res.status(404).json({ success: false, message: "User not found" });
      return;
    }

    res.json({
      success: true,
      data: { user },
    });
  } catch (error) {
    console.error("Me error:", error);
    res.status(500).json({ success: false, message: "Something went wrong!" });
  }
});

export default router;
