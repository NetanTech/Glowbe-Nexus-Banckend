import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

import { pool } from "../config/database";

(async () => {
  const file = path.join(__dirname, "../../db/schema.sql");
  const sql = fs.readFileSync(file, "utf8");
  await pool.query(sql);
  console.log("Schema applied");
  await pool.end();
})().catch(async (error) => {
  console.error(error);
  await pool.end();
  process.exit(1);
});
