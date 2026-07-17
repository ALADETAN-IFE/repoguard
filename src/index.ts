import "dotenv/config";
import express from "express";
import helmet from "helmet";
import logger from "./utils/logger";
import router from "./routes";
import { connectDatabase } from "./config/db";
import { resumeIncompleteScans } from "./utils/autoResume";

const app = express();

app.set("trust proxy", 1);
app.use(helmet());

app.use((req, res, next) => {
  if (req.path === "/api/webhook") return next();
  express.json({ limit: "1mb" })(req, res, next);
});
app.use("/", router);

const PORT = parseInt(process.env.PORT ?? "3000", 10);

async function start(): Promise<void> {
  // Connect to MongoDB before accepting any traffic
  await connectDatabase();

  app.listen(PORT, () => {
    const baseUrl = process.env.RAILWAY_PUBLIC_DOMAIN
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : `http://localhost:${PORT}`;

    setInterval(
      () => {
        void fetch(`${baseUrl}/health`)
          .then(() => logger.info("[keepalive] ping sent"))
          .catch(() => logger.warn("[keepalive] ping failed"));
      },
      14 * 60 * 1000,
    );

    logger.info(`RepoGuard running on port ${PORT}`);
    logger.info(`Webhook endpoint: ${baseUrl}/api/webhook`);

    void resumeIncompleteScans();
  });
}

void start();
