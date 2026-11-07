// src/app.ts
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";

import { getJwtSecret } from "./config/jwt";
import { apiLimiter } from "./middleware/rateLimit";
import authRoutes from "./routes/auth";

// Fail fast if JWT_SECRET is missing
getJwtSecret();

const app = express();

app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS ?? 1));

const PORT = process.env.PORT || 3003;

// ====================
// Middleware
// ====================
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  })
);

const normalizeOrigin = (value: string) => value.trim().replace(/\/+$/, "");

const defaultAllowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
];

const envOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => normalizeOrigin(o))
  .filter(Boolean);

const frontendOrigin = process.env.FRONTEND_URL
  ? normalizeOrigin(process.env.FRONTEND_URL)
  : "";

const allowedOrigins = Array.from(
  new Set([
    ...defaultAllowedOrigins.map(normalizeOrigin),
    ...envOrigins,
    ...(frontendOrigin ? [frontendOrigin] : []),
  ])
);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      const normalized = normalizeOrigin(origin);
      if (allowedOrigins.includes(normalized)) return callback(null, true);

      if (process.env.NODE_ENV !== "production" && normalized.includes("localhost")) {
        return callback(null, true);
      }

      console.warn("[CORS] Blocked origin:", origin);
      return callback(null, false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Cache-Control",
      "Pragma",
      "Expires",
      "X-Requested-With",
      "Accept",
      "Origin",
    ],
    optionsSuccessStatus: 204,
  })
);

morgan.token("remote-addr", (req) => {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || "-";
});

app.use(
  morgan("combined", {
    skip: (req) => {
      const path = req.path || "";
      return path === "/health" || path === "/";
    },
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/api", apiLimiter);

// ====================
// Health check
// ====================
app.get("/health", (_req, res) => {
  res.json({
    status: "OK",
    message: "Glowbe Nexus Backend is running!",
    timestamp: new Date().toISOString(),
  });
});

// ====================
// Root
// ====================
app.get("/", (_req, res) => {
  res.json({
    message: "Welcome to Glowbe Nexus API",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      auth: "/api/auth",
    },
  });
});

// ====================
// API Routes
// ====================
app.use("/api/auth", authRoutes);

// ====================
// Global error handler
// ====================
app.use(
  (
    err: any,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction
  ) => {
    console.error(err.stack);
    res.status(500).json({
      success: false,
      message: "Something went wrong!",
      error: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }
);

// ====================
// 404 handler - MUST BE LAST
// ====================
app.use((_req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// ====================
// Local server only
// ====================
app.listen(PORT, () => {
  console.log(`🚀 Glowbe Nexus Backend running on port ${PORT}`);
});

export default app;
