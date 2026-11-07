import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import {
  getJwtSecret,
  JWT_EXPIRES_IN,
  JWT_REFRESH_EXPIRES_IN,
  JWT_TEMP_EXPIRES_IN,
  OTP_CONFIG,
} from "../config/jwt";

export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 12);
};

export const comparePassword = async (
  password: string,
  hashedPassword: string
): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword);
};

export const generateAccessToken = (
  userId: string,
  email: string,
  tokenVersion: number = 0
): string => {
  return jwt.sign(
    {
      userId,
      email,
      type: "access",
      tv: tokenVersion,
      iat: Math.floor(Date.now() / 1000),
    },
    getJwtSecret(),
    { expiresIn: JWT_EXPIRES_IN }
  );
};

export const generateRefreshToken = (
  userId: string,
  tokenVersion: number = 0
): string => {
  return jwt.sign(
    {
      userId,
      type: "refresh",
      tv: tokenVersion,
      iat: Math.floor(Date.now() / 1000),
    },
    getJwtSecret(),
    { expiresIn: JWT_REFRESH_EXPIRES_IN }
  );
};

export const generateTemporaryToken = (
  userId: string,
  email: string,
  expiresInSeconds: number = 600
): string => {
  return jwt.sign(
    {
      userId,
      email,
      type: "temp",
      iat: Math.floor(Date.now() / 1000),
    },
    getJwtSecret(),
    { expiresIn: expiresInSeconds }
  );
};

export const verifyToken = (token: string): any => {
  try {
    return jwt.verify(token, getJwtSecret());
  } catch {
    throw new Error("Invalid token");
  }
};

export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const validatePassword = (
  password: string
): { isValid: boolean; message?: string } => {
  if (password.length < 8) {
    return { isValid: false, message: "Password must be at least 8 characters long" };
  }
  if (!/(?=.*[a-z])/.test(password)) {
    return {
      isValid: false,
      message: "Password must contain at least one lowercase letter",
    };
  }
  if (!/(?=.*[A-Z])/.test(password)) {
    return {
      isValid: false,
      message: "Password must contain at least one uppercase letter",
    };
  }
  if (!/(?=.*\d)/.test(password)) {
    return { isValid: false, message: "Password must contain at least one number" };
  }
  return { isValid: true };
};

export const generateSecureOTP = (length: number = OTP_CONFIG.length): string => {
  const digits = "0123456789";
  let otp = "";
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    otp += digits[randomBytes[i] % digits.length];
  }
  return otp;
};

export const hashRefreshToken = async (refreshToken: string): Promise<string> => {
  return bcrypt.hash(refreshToken, 10);
};

export { JWT_TEMP_EXPIRES_IN, OTP_CONFIG };
