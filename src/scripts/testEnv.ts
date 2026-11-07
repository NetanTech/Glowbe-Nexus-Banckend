import dotenv from "dotenv";
dotenv.config();

const required = ["SUPABASE_URL", "SUPABASE_ANON_KEY", "JWT_SECRET"];

let ok = true;
for (const key of required) {
  const present = Boolean(process.env[key]?.trim());
  console.log(`${key}: ${present ? "EXISTS" : "MISSING"}`);
  if (!present) ok = false;
}

process.exit(ok ? 0 : 1);
