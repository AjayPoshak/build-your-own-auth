import { createClient } from "redis";
import log from "pino";

const logger = log();

export class Cache {
  constructor() {
    this.client = createClient();
    this.isClientConnected = false;
  }

  async connectClient() {
    if (this.isClientConnected === false) {
      logger.info("Opening connection to redis");
      await this.client.connect();
      this.isClientConnected = true;
    }
  }

  async set(key, value, expiry) {
    await this.connectClient();
    if (expiry) {
      await this.client.set(key, value, { EX: expiry });
      logger.info(
        "Cache:: SET key: " + key + " value: ",
        value,
        " expiry: " + expiry
      );
    } else {
      await this.client.set(key, value);
      logger.info("Cache:: SET key: " + key + " value: ", value);
    }
  }

  async get(key) {
    await this.connectClient();
    await this.client.get(key);
    logger.info("Cache:: GET key: " + key);
  }
}
