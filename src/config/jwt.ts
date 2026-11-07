/**
 * Central JWT configuration. Never fall back to a hardcoded secret.
 */
export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET?.trim();
  if (!secret) {
    throw new Error(
      "JWT_SECRET environment variable is required. Refusing to start with an insecure default."
    );
  }
  return secret;
}

export const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "8h";
export const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "30d";
export const JWT_TEMP_EXPIRES_IN = process.env.JWT_TEMP_EXPIRES_IN || "10m";

export const OTP_CONFIG = {
  length: parseInt(process.env.OTP_LENGTH || "6", 10),
  expiresIn: parseInt(process.env.OTP_EXPIRES_IN || "600", 10),
  maxAttempts: parseInt(process.env.OTP_MAX_ATTEMPTS || "5", 10),
  blockDuration: parseInt(process.env.OTP_BLOCK_DURATION || "900", 10),
};
