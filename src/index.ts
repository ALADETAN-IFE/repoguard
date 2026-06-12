import "dotenv/config";
import express from "express";
import logger from "./utils/logger";
import router from "./routes";
import { connectDatabase } from "./config/db";
import { resumeIncompleteScans } from "./utils/autoResume";

const app = express();

app.use(express.json());
app.use("/", router);

const PORT = parseInt(process.env.PORT ?? "3000", 10);

async function start(): Promise<void> {
  // Connect to MongoDB before accepting any traffic
  await connectDatabase();

  app.listen(PORT, () => {
    const baseUrl = process.env.RAILWAY_PUBLIC_DOMAIN 
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${PORT}`;

    logger.info(`RepoGuard running on port ${PORT}`);
    logger.info(`Webhook endpoint: ${baseUrl}/api/webhook`);

    void resumeIncompleteScans();
  });
}

void start();