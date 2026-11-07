import { Pool, QueryResultRow } from "pg";
import dotenv from "dotenv";

dotenv.config();

function connectionString() {
  const raw = process.env.DATABASE_URL_POOLED || process.env.DATABASE_URL;
  if (!raw) {
    throw new Error("Missing DATABASE_URL");
  }

  const url = new URL(raw);
  url.searchParams.delete("channel_binding");
  return url.toString();
}

export const pool = new Pool({
  connectionString: connectionString(),
  ssl: { rejectUnauthorized: false },
  max: 10,
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
) {
  const result = await pool.query<T>(text, params);
  return result.rows;
}

export async function queryOne<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
) {
  const rows = await query<T>(text, params);
  return rows[0] ?? null;
}

export const testConnection = async () => {
  try {
    await pool.query("select 1");
    console.log("Database connected successfully");
    return true;
  } catch (error) {
    console.error("Database connection failed:", error);
    return false;
  }
};
