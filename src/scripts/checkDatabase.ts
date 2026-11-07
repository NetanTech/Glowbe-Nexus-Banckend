import dotenv from "dotenv";
dotenv.config();

import { testConnection } from "../config/database";

(async () => {
  const ok = await testConnection();
  process.exit(ok ? 0 : 1);
})();
