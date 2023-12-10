import http from "node:http";
import log from "pino";
const { randomBytes } = await import("node:crypto");
import { Service } from "./service.js";

const LOGIN_DURATION_SECONDS = 120;

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
        const { token } = await service.createSession({ email });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "login successful", token: token }));
        return;
      }
    } catch (err) {
      console.error(err);
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Unauthorized: Invalid username or password");
      return;
    }
  } else if (req.method === "POST" && req.url === "/validate-session") {
    logger.info("Validating session");
    const rawData = await parseBody(req);
    const body = JSON.parse(rawData);
    const { sessionToken } = body;
    if (!sessionToken) {
      logger.warn("No token found");
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("Unauthorized: Invalid/Missing Token");
      return;
    }
    try {
      const validationResults = await service.validateSession({ sessionToken });
      logger.info(validationResults.results);
      if (validationResults.results.length === 0) {
        res.writeHead(401, { "Content-Type": "text/plain" });
        res.end("Unauthorized: Invalid/Missing Token");
        return;
      }
      const { secondsSinceCreated } = validationResults?.results?.[0];
      logger.info("time elpased ", secondsSinceCreated);
      if (secondsSinceCreated > LOGIN_DURATION_SECONDS) {
        await service.forceLogout({ sessionToken });
        logger.warn("Forcing logout, token expired");
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

// server.close(() => {
//   console.log("Closing the server");
//   connection.end();
// });
