import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { queryOne } from "../config/database";
import { getJwtSecret } from "../config/jwt";

export interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    name: string;
    role: "user" | "admin";
    account_status: "active" | "suspended" | "banned" | "pending";
    email_verified: boolean;
  };
}

const USER_SELECT = `
  user_id,
  email,
  name,
  role,
  account_status,
  email_verified
`;

export const authenticateToken = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : undefined;

    if (!token) {
      res.status(401).json({ success: false, message: "Access token required" });
      return;
    }

    const decoded = jwt.verify(token, getJwtSecret()) as {
      userId: string;
      email: string;
      type?: string;
    };

    if (decoded.type && decoded.type !== "access") {
      res.status(401).json({ success: false, message: "Invalid access token" });
      return;
    }

    const user = await queryOne<{
      user_id: string;
      email: string;
      name: string;
      role: "user" | "admin";
      account_status: "active" | "suspended" | "banned" | "pending";
      email_verified: boolean;
    }>(
      `select ${USER_SELECT} from users where user_id = $1`,
      [decoded.userId]
    );

    if (!user) {
      res.status(401).json({ success: false, message: "User not found" });
      return;
    }

    if (user.account_status === "suspended" || user.account_status === "banned") {
      res.status(403).json({
        success: false,
        message: "Account is not allowed to access this resource",
      });
      return;
    }

    req.user = {
      id: user.user_id,
      email: user.email,
      name: user.name,
      role: user.role,
      account_status: user.account_status,
      email_verified: Boolean(user.email_verified),
    };

    next();
  } catch {
    res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
};

export const authenticateTemporary = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : undefined;

    if (!token) {
      res.status(401).json({ success: false, message: "Temporary token required" });
      return;
    }

    const decoded = jwt.verify(token, getJwtSecret()) as {
      userId: string;
      email: string;
      type?: string;
    };

    if (decoded.type !== "temp") {
      res.status(401).json({ success: false, message: "Invalid temporary token" });
      return;
    }

    req.user = {
      id: decoded.userId,
      email: decoded.email,
      name: "",
      role: "user",
      account_status: "pending",
      email_verified: false,
    };

    next();
  } catch {
    res.status(401).json({
      success: false,
      message: "Invalid or expired temporary token",
    });
  }
};
