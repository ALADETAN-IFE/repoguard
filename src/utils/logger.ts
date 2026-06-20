import { createLogger, format, transports } from "winston";

const logger = createLogger({
  level: process.env.LOG_LEVEL ?? "info",
  format: format.combine(
    format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    format.errors({ stack: true }),
    format.printf(({ timestamp, level, message, stack }) => {
      const ts = timestamp as string;
      const msg = message as string;
      const st = stack as string | undefined;
      return st
        ? `[${ts}] ${level.toUpperCase()}: ${msg}\n${st}`
        : `[${ts}] ${level.toUpperCase()}: ${msg}`;
    }),
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: "logs/error.log", level: "error" }),
    new transports.File({ filename: "logs/combined.log" }),
  ],
});

export default logger;
