export interface User {
  user_id: string;
  name: string;
  email: string;
  password?: string;
  profile_picture?: string;
  role: "user" | "admin";
  phone_number?: string;
  email_verified: boolean;
  account_status: "active" | "suspended" | "banned" | "pending";
  token_version?: number;
  created_at: Date;
  updated_at: Date;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  user: Omit<User, "password">;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
  phone_number?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}
