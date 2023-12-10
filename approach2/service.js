import mysql from "mysql2";
import log from "pino";
import { randomBytes } from "node:crypto";
import { Cache } from "./cache.js";

const { createHash } = await import("node:crypto");

const LOGIN_DURATION_SECONDS = 120;

const logger = log();

const connection = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

connection.connect();

export class Service {
  constructor() {
    this.cache = new Cache();
  }

  async createUser({ email, password }) {
    return new Promise((resolve, reject) => {
      const hash = createHash("sha256");
      const salt = randomBytes(10).toString("hex");
      console.log({ salt });
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
        async (err, results) => {
          try {
            // Store the created session token to redis
            await this.cache.set(email, token, LOGIN_DURATION_SECONDS);
          } catch (err) {
            reject(err);
            return;
          }
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

  async validateSession({ email, sessionToken }) {
    return new Promise(async (resolve, reject) => {
      logger.info("validateSession called for " + sessionToken);
      const isEmailInCache = await this.cache.get(email);
      if (isEmailInCache) {
        logger.info("Found token in Cache");
        const token = await this.cache.get(email);
        if (token) {
          resolve({ isValid: true, sessionToken });
          return;
        }
      }
      connection.execute(
        "SELECT session_id, timestampdiff(second, created_at, now()) AS secondsSinceCreated, timestampdiff(second, created_at, now()) FROM sessions WHERE session_id = ? AND is_active = true",
        [sessionToken],
        async (err, results) => {
          logger.info("session validated " + JSON.stringify(results));
          if (results.length === 0) {
            resolve({ isValid: false, sessionToken: null });
            return;
          }
          console.log(results);
          const { secondsSinceCreated } = results?.[0];
          if (secondsSinceCreated > LOGIN_DURATION_SECONDS) {
            await this.forceLogout({ sessionToken });
            resolve({ isValid: false, sessionToken: null });
            return;
          }
          resolve({ isValid: true, sessionToken });
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
