import mysql from "mysql2";
import log from "pino";
import { randomBytes } from "node:crypto";
const { createHash } = await import("node:crypto");

const logger = log();

const connection = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

connection.connect();

export class Service {
  async createUser({ email, password }) {
    return new Promise((resolve, reject) => {
      const hash = createHash("sha256");
      const salt = randomBytes(10).toString("hex");
      const hashedPassword = hash.update(password + salt).digest("hex");
      connection.execute(
        "INSERT INTO users (email, password, salt) VALUES (?, ?, ?)",
        [email, hashedPassword, salt],
        (err, results, fields) => {
          logger.info("results " + JSON.stringify(results));
          logger.info("fields " + JSON.stringify(fields));
          resolve(results, fields);
          if (err) {
            console.error(err);
            reject(err);
          }
        }
      );
    });
  }

  async getSalt({ email }) {
    return new Promise((resolve, reject) => {
      logger.info("getSalt called");
      connection.execute(
        "SELECT email, salt from `users` WHERE email = ?",
        [email],
        (err, results, fields) => {
          logger.info("results " + JSON.stringify(results));
          resolve({ results, fields });
          if (err) {
            logger.error(err);
            reject(err);
          }
        }
      );
    });
  }

  async loginUser({ email, password }) {
    return new Promise(async (resolve, reject) => {
      logger.info("loginUser called");
      const { results } = await this.getSalt({ email });
      if (results.length === 0) {
        reject("Email does not exists");
        return;
      }
      const { salt } = results[0];
      const hash = createHash("sha256");
      const hashedPassword = hash.update(password + salt).digest("hex");
      connection.execute(
        "SELECT email, password from `users` WHERE email = ? AND password = ?",
        [email, hashedPassword],
        (err, results, fields) => {
          logger.info("results " + JSON.stringify(results));
          resolve({ results, fields });
          if (err) {
            logger.error(err);
            reject(err);
          }
        }
      );
    });
  }

  async createSession({ email }) {
    return new Promise(async (resolve, reject) => {
      logger.info("createSession called for " + email);
      const token = randomBytes(10).toString("hex");
      connection.execute(
        "INSERT INTO sessions (email, session_id, is_active) VALUES (?, ?, true)",
        [email, token],
        (err, results) => {
          logger.info("session created " + JSON.stringify(results));
          resolve({ results, token });
          if (err) {
            logger.error(err);
            reject(err);
          }
        }
      );
    });
  }

  async validateSession({ sessionToken }) {
    return new Promise(async (resolve, reject) => {
      logger.info("validateSession called for " + sessionToken);
      connection.execute(
        "SELECT session_id, timestampdiff(second, created_at, now()) AS secondsSinceCreated, timestampdiff(second, created_at, now()) FROM sessions WHERE session_id = ? AND is_active = true",
        [sessionToken],
        (err, results) => {
          logger.info("session validated " + JSON.stringify(results));
          resolve({ results });
          if (err) {
            logger.error(err);
            reject(err);
          }
        }
      );
    });
  }

  async forceLogout({ sessionToken }) {
    return new Promise(async (resolve, reject) => {
      logger.info("forceLogout called for " + sessionToken);
      connection.execute(
        "UPDATE sessions SET is_active = false WHERE session_id = ?",
        [sessionToken],
        (err, results) => {
          logger.info("user forced logged out" + JSON.stringify(results));
          resolve({ results });
          if (err) {
            logger.error(err);
            reject(err);
          }
        }
      );
    });
  }
}
