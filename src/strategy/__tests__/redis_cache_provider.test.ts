// tslint:disable: no-object-mutation
import { isRight } from "fp-ts/lib/Either";
import { createMockRedis } from "mock-redis-client";
import { SamlConfig } from "passport-saml";
import { RedisClient } from "redis";
import {
  getExtendedRedisCacheProvider,
  noopCacheProvider,
  SAMLRequestCacheItem
} from "../redis_cache_provider";

const mockSet = jest.fn();
const mockGet = jest.fn();
const mockDel = jest.fn();

// tslint:disable-next-line: no-any
const mockRedisClient: RedisClient = (createMockRedis() as any).createClient();
mockRedisClient.set = mockSet;
mockRedisClient.get = mockGet;
mockRedisClient.del = mockDel;

const keyExpirationPeriodSeconds = 3600;
const expectedRequestID = "_ab0c7302158bde147963";
const SAMLRequest = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${expectedRequestID}" Version="2.0" 
  IssueInstant="2020-02-17T10:20:28.417Z"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Destination="http://localhost:8080/samlsso" ForceAuthn="true" 
  AssertionConsumerServiceURL="http://localhost:3000/acs" AttributeConsumingServiceIndex="0">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    NameQualifier="https://spid.agid.gov.it/cd" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://spid.agid.gov.it/cd</saml:Issuer>
  <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
  <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
  <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://www.spid.gov.it/SpidL2</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

const samlConfig: SamlConfig = {
  idpIssuer: "http://localhost:8080/"
};

describe("noopCacheProvider", () => {
  const mockCallback = jest.fn();
  const expectedKey = "SAML-XXX";
  const expectedValue = "Value";
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("should save method of noopCacheProvider do noting", () => {
    noopCacheProvider().save(expectedKey, expectedValue, mockCallback);
    expect(mockCallback).toBeCalledWith(null, {
      createdAt: expect.any(Date),
      value: expectedValue
    });
  });
  it("should get method of noopCacheProvider do noting", () => {
    noopCacheProvider().get(expectedKey, mockCallback);
    expect(mockCallback).toBeCalledWith(null, {});
  });
  it("should remove method of noopCacheProvider do noting", () => {
    noopCacheProvider().remove(expectedKey, mockCallback);
    expect(mockCallback).toBeCalledWith(null, expectedKey);
  });
});

describe("getExtendedRedisCacheProvider#save", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("should return the saved SAML Request data", async () => {
    mockSet.mockImplementation((_, __, ___, ____, callback) =>
      callback(null, "OK")
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .save(SAMLRequest, samlConfig)
      .run();
    expect(mockSet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(mockSet.mock.calls[0][1]).toEqual(expect.any(String));
    expect(mockSet.mock.calls[0][2]).toBe("EX");
    expect(mockSet.mock.calls[0][3]).toBe(keyExpirationPeriodSeconds);
    expect(isRight(cacheSAMLResponse)).toBeTruthy();
    expect(cacheSAMLResponse.value).toEqual({
      RequestXML: SAMLRequest,
      createdAt: expect.any(Date),
      idpIssuer: samlConfig.idpIssuer
    });
  });
  it("should return an error if save on radis fail", async () => {
    const expectedRedisError = new Error("saveError");
    mockSet.mockImplementation((_, __, ___, ____, callback) =>
      callback(expectedRedisError)
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .save(SAMLRequest, samlConfig)
      .run();
    expect(mockSet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(mockSet.mock.calls[0][1]).toEqual(expect.any(String));
    expect(mockSet.mock.calls[0][2]).toBe("EX");
    expect(mockSet.mock.calls[0][3]).toBe(keyExpirationPeriodSeconds);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    expect(cacheSAMLResponse.value).toEqual(
      new Error(
        `SAML#ExtendedRedisCacheProvider: set() error ${expectedRedisError}`
      )
    );
  });
  it("should return an error if idpIssuer is missing inside samlConfig", async () => {
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .save(SAMLRequest, {})
      .run();
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    expect(cacheSAMLResponse.value).toEqual(
      new Error("Missing idpIssuer inside configuration")
    );
  });
  it("should return an error if Request ID is missing", async () => {
    const SAMLRequestWithoutID = SAMLRequest.replace(
      `ID="${expectedRequestID}"`,
      ""
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .save(SAMLRequestWithoutID, samlConfig)
      .run();
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    expect(cacheSAMLResponse.value).toEqual(
      new Error(`SAML#ExtendedRedisCacheProvider: missing AuthnRequest ID`)
    );
  });
});

describe("getExtendedRedisCacheProvider#save", () => {
  it("should return the saved SAML Request data if exists", async () => {
    const expectedRequestData: SAMLRequestCacheItem = {
      RequestXML: SAMLRequest,
      createdAt: new Date(),
      // tslint:disable-next-line: no-useless-cast
      idpIssuer: samlConfig.idpIssuer as string
    };
    mockGet.mockImplementation((_, callback) =>
      callback(null, JSON.stringify(expectedRequestData))
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .get(expectedRequestID)
      .run();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeTruthy();
    expect(cacheSAMLResponse.value).toEqual(expectedRequestData);
  });
  it("should return an error if the reading process on redis fail", async () => {
    const expectedRedisError = new Error("readError");
    mockGet.mockImplementation((_, callback) => callback(expectedRedisError));
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .get(expectedRequestID)
      .run();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    expect(cacheSAMLResponse.value).toEqual(
      new Error(
        `SAML#ExtendedRedisCacheProvider: get() error ${expectedRedisError}`
      )
    );
  });
  it("should return an error cached Request is not compliant", async () => {
    const invalidCachedRequestData = {
      RequestXML: SAMLRequest,
      createdAt: new Date(),
      idpIssuer: undefined
    };
    mockGet.mockImplementation((_, callback) =>
      callback(null, JSON.stringify(invalidCachedRequestData))
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .get(expectedRequestID)
      .run();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    expect(cacheSAMLResponse.value).toEqual(expect.any(Error));
  });
  it("should return an error is the cached Request is missing", async () => {
    mockGet.mockImplementation((_, callback) => callback(null, null));
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const cacheSAMLResponse = await redisCacheProvider
      .get(expectedRequestID)
      .run();
    expect(mockGet.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(cacheSAMLResponse)).toBeFalsy();
    expect(cacheSAMLResponse.value).toEqual(expect.any(Error));
  });
});

describe("getExtendedRedisCacheProvider#remove", () => {
  it("should return the RequestID if the deletion process succeded", async () => {
    mockDel.mockImplementation((_, callback) => callback(null, 1));
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const maybeRequestId = await redisCacheProvider
      .remove(expectedRequestID)
      .run();
    expect(mockDel.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(maybeRequestId)).toBeTruthy();
    expect(maybeRequestId.value).toBe(expectedRequestID);
  });

  it("should return an error if the cache's deletion fail", async () => {
    const expectedDelRedisError = new Error("delError");
    mockDel.mockImplementation((_, callback) =>
      callback(expectedDelRedisError)
    );
    const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);
    const maybeRequestId = await redisCacheProvider
      .remove(expectedRequestID)
      .run();
    expect(mockDel.mock.calls[0][0]).toBe(`SAML-EXT-${expectedRequestID}`);
    expect(isRight(maybeRequestId)).toBeFalsy();
    expect(maybeRequestId.value).toEqual(
      new Error(
        `SAML#ExtendedRedisCacheProvider: remove() error ${expectedDelRedisError}`
      )
    );
  });
});
