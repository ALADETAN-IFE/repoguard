import "dotenv/config";
import express from "express";
import logger from "./utils/logger";
import router from "./routes";
import { resumeIncompleteScans } from "./utils/autoResume";

const app = express();

app.use(express.json());
app.use("/", router);

const PORT = parseInt(process.env.PORT ?? "3000", 10);

app.listen(PORT, () => {
  logger.info(`RepoGuard running on port ${PORT}`);
  logger.info(`Webhook endpoint: http://localhost:${PORT}/api/webhook`);

  void resumeIncompleteScans();
});
