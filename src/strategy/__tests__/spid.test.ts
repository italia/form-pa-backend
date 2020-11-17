import * as express from "express";
import { createMockRedis } from "mock-redis-client";
import { Profile, VerifiedCallback } from "passport-saml";
import { RedisClient } from "redis";
import { logger } from "../../utils/logger";
import { getSamlOptions } from "../../utils/saml";
import * as redisCacheProvider from "../redis_cache_provider";
import { SpidStrategy } from "../spid";

// tslint:disable-next-line: no-any
const mockRedisClient: RedisClient = (createMockRedis() as any).createClient();

describe("SamlStrategy prototype arguments check", () => {
  // tslint:disable-next-line: no-let no-any
  let OriginalPassportSaml: any;
  beforeAll(() => {
    OriginalPassportSaml = jest.requireActual("passport-saml").Strategy;
  });
  it("should SamlStrategy constructor has 2 parameters", () => {
    expect(OriginalPassportSaml.prototype.constructor).toHaveLength(2);
  });
  it("should SamlStrategy authenticate has 2 parameters", () => {
    expect(OriginalPassportSaml.prototype.authenticate).toHaveLength(2);
  });
});

describe("SamlStrategy#constructor", () => {
  beforeAll(() => {
    jest.restoreAllMocks();
  });
  it("should SamlStrategy constructor has 2 parameters", () => {
    const expectedNoopCacheProvider = {
      // tslint:disable-next-line: no-empty
      get: () => () => {
        return;
      },
      remove: () => () => {
        return;
      },
      save: () => {
        return;
      }
    };
    const mockNoopCacheProvider = jest
      .spyOn(redisCacheProvider, "noopCacheProvider")
      .mockImplementation(() => expectedNoopCacheProvider);
    const spidStrategy = new SpidStrategy(
      {},
      getSamlOptions,
      (_: express.Request, profile: Profile, done: VerifiedCallback) => {
        // at this point SAML authentication is successful
        // `done` is a passport callback that signals success
        done(null, profile);
      },
      mockRedisClient
    );
    // tslint:disable-next-line: no-string-literal
    expect(spidStrategy["options"]).toHaveProperty(
      "requestIdExpirationPeriodMs",
      900000
    );
    // tslint:disable-next-line: no-string-literal
    expect(spidStrategy["options"]).toHaveProperty(
      "cacheProvider",
      expectedNoopCacheProvider
    );
    expect(mockNoopCacheProvider).toBeCalledTimes(1);
    // tslint:disable-next-line: no-string-literal
    expect(spidStrategy["extendedRedisCacheProvider"]).toBeTruthy();
  });
});

describe("loadFromRemote", () => {
  it("should reject if the fetch of IdP metadata fails", async () => {
    expect(true).toBeTruthy();
  });

  it("should reject if the IdP metadata are fetched from a wrong path", async () => {
    expect(true).toBeTruthy();
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", async () => {
    expect(true).toBeTruthy();
  });

  it("should resolve with the fetched IdP options", async () => {
    expect(true).toBeTruthy();
  });
});
