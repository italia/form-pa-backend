import { createLogger, format, transports } from "winston";
const { combine, timestamp, label, printf } = format;

export const logger = createLogger({
  format: combine(
    label({ label: "io-spid-commons" }),
    timestamp(),
    format.splat(),
    printf(info => {
      return `${info.timestamp} [${info.label}] ${info.level}: ${info.message}`;
    })
  ),
  level: process.env.NODE_ENV !== "production" ? "debug" : "info",
  transports: [new transports.Console()]
});
