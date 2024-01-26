import http from "node:http";
import log from "pino";
const { randomBytes } = await import("node:crypto");
import { Service } from "../service.js";
import {JWT} from './jwt.js'

const logger = log();

async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    req.on("data", (chunk) => {
      chunks.push(chunk);
    });
    req.on("end", () => {
      const data = Buffer.concat(chunks);
      resolve(data.toString());
    });
  });
}

const jwt = new JWT('../private_key.pem', '../public_key.pem')

const server = http.createServer(async (req, res) => {
  const service = new Service();
  if (req.method === "POST" && req.url === "/signup") {
    const rawData = await parseBody(req);
    const body = JSON.parse(rawData);
    logger.info("Signing up ", body);
    const { email, password } = body;
    if (!email || !password) {
      //Send Error response back
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("invalid username or password");
      return;
    }
    await service.createUser({ email, password });
  } else if (req.method === "POST" && req.url === "/login") {
    logger.info("/login called");
    const rawData = await parseBody(req);
    const body = JSON.parse(rawData);
    const { email, password } = body;
    if (!email || !password) {
      logger.warn("Invalid username or password");
      //Send Error response back
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("invalid username or password");
      return;
    }
    try {
      const response = await service.loginUser({ email, password });
      if (response.results.length === 0) {
        res.writeHead(401, { "Content-Type": "text/plain" });
        res.end("Unauthorized: Invalid username or password");
        return;
      } else {
        logger.info("Login successful for " + email);
        const token = jwt.sign({email})
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "login successful", token: token }));
        return;
      }
    } catch (err) {
      logger.error(err);
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Unauthorized: Invalid username or password");
      return;
    }
  } else if (req.method === "POST" && req.url === "/validate-session") {
    logger.info("Validating session");
    const rawData = await parseBody(req);
    const body = JSON.parse(rawData);
    const { sessionToken, email } = body;
    if (!sessionToken) {
      logger.warn("No token found");
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("Unauthorized: Invalid/Missing Token");
      return;
    }
    if (!email) {
      logger.warn("No email found");
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("Unauthorized: Invalid/Missing Email");
      return;
    }
    try {
      const isValid = jwt.verify(sessionToken)
      logger.info({ isValid, sessionToken });
      if (isValid === false) {
        res.writeHead(401, { "Content-Type": "text/plain" });
        res.end("Unauthorized: Invalid/Missing Token");
        return;
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ message: "valid session", token: sessionToken })
        );
        return;
      }
    } catch (err) {
      logger.error(err);
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("Unauthorized: Expired Token");
    }
  }
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("okay");
});

server.listen(4100, () => {
  console.log("Server started at 4100");
});
