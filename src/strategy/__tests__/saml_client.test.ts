// tslint:disable: no-object-mutation
import { left, right } from "fp-ts/lib/Either";
import { fromEither } from "fp-ts/lib/TaskEither";
import { createMockRedis } from "mock-redis-client";
import { RedisClient } from "redis";
import { Builder } from "xml2js";
import mockReq from "../../__mocks__/request";
import { IServiceProviderConfig } from "../../utils/middleware";
import { getAuthorizeRequestTamperer } from "../../utils/saml";
import { mockWrapCallback } from "../__mocks__/passport-saml";
import { getExtendedRedisCacheProvider } from "../redis_cache_provider";
import { CustomSamlClient } from "../saml_client";
import { PreValidateResponseT } from "../spid";

const mockSet = jest.fn();
const mockGet = jest.fn();
const mockDel = jest.fn();

// tslint:disable-next-line: no-any
const mockRedisClient: RedisClient = (createMockRedis() as any).createClient();
mockRedisClient.set = mockSet;
mockRedisClient.get = mockGet;
mockRedisClient.del = mockDel;

const redisCacheProvider = getExtendedRedisCacheProvider(mockRedisClient);

const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl:
    "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml",
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name"
  },
  publicCert: "",
  requiredAttributes: {
    attributes: [
      "address",
      "email",
      "name",
      "familyName",
      "fiscalNumber",
      "mobilePhone"
    ],
    name: "Required attrs"
  },
  spidCieUrl: "https://idserver.servizicie.interno.gov.it:8443/idp/shibboleth",
  spidTestEnvUrl: "https://spid-testenv2:8088",
  spidValidatorUrl: "http://localhost:8080"
};
const expectedRequestID = "123456";
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

const authReqTampener = getAuthorizeRequestTamperer(
  // spid-testenv does not accept an xml header with utf8 encoding
  new Builder({ xmldec: { encoding: undefined, version: "1.0" } }),
  serviceProviderConfig,
  {}
);

const mockedCallback = jest.fn();

describe("SAML prototype arguments check", () => {
  // tslint:disable-next-line: no-let no-any
  let OriginalPassportSaml: any;
  beforeAll(() => {
    OriginalPassportSaml = jest.requireActual("passport-saml");
  });
  afterAll(() => {
    jest.restoreAllMocks();
  });

  it("should SAML constructor has 2 parameters", () => {
    expect(OriginalPassportSaml.SAML.prototype.constructor).toHaveLength(1);
  });
  it("should SAML validatePostResponse has 2 parameters", () => {
    expect(
      OriginalPassportSaml.SAML.prototype.validatePostResponse
    ).toHaveLength(2);
  });
  it("should SAML generateAuthorizeRequest has 3 parameters", () => {
    expect(
      OriginalPassportSaml.SAML.prototype.generateAuthorizeRequest
    ).toHaveLength(3);
  });
});

describe("CustomSamlClient#constructor", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("should CustomSamlClient constructor call SAML constructor with overrided validateInResponseTo", () => {
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider
    );
    expect(customSamlClient).toBeTruthy();
    // tslint:disable-next-line: no-string-literal
    expect(customSamlClient["options"]).toHaveProperty(
      "validateInResponseTo",
      false
    );
  });
});

describe("CustomSamlClient#validatePostResponse", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("should validatePostResponse call SAML validatePostResponse", () => {
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockedCallback).toBeCalledTimes(1);
  });

  it("should validatePostResponse calls preValidateResponse if provided into CustomSamlClient", () => {
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback();
      });
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    expect(mockedCallback).toBeCalledTimes(1);
  });

  it("should preValidateResponse forward the error when occours", () => {
    const expectedPreValidateError = new Error("PreValidateError");
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(expectedPreValidateError);
      });
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    expect(mockedCallback).toBeCalledWith(expectedPreValidateError);
    expect(mockedCallback).toBeCalledTimes(1);
  });

  it("should remove cached Response if preValidateResponse and validatePostResponse succeded", async () => {
    const expectedAuthnRequestID = "123456";
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(null, true, expectedAuthnRequestID);
      });
    mockDel.mockImplementation((_, callback) => callback(null, 1));
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise(resolve => {
      setTimeout(() => {
        expect(mockDel).toBeCalledWith(
          `SAML-EXT-${expectedAuthnRequestID}`,
          expect.any(Function)
        );
        expect(mockedCallback).toBeCalledWith(null, {}, false);
        resolve();
      }, 100);
    });
  });

  it("should validatePostResponse return an error if an error occurs deleting the SAML Request", async () => {
    const expectedAuthnRequestID = "123456";
    const expectedDelError = new Error("ErrorDel");
    const mockPreValidate = jest
      .fn()
      .mockImplementation((_, __, ___, ____, callback) => {
        callback(null, true, expectedAuthnRequestID);
      });
    mockDel.mockImplementation((_, callback) => callback(expectedDelError));
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider,
      authReqTampener,
      mockPreValidate
    );
    expect(customSamlClient).toBeTruthy();
    customSamlClient.validatePostResponse({ SAMLResponse: "" }, mockedCallback);
    expect(mockPreValidate).toBeCalledWith(
      { validateInResponseTo: true },
      { SAMLResponse: "" },
      redisCacheProvider,
      undefined,
      expect.any(Function)
    );
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise(resolve => {
      setTimeout(() => {
        expect(mockDel).toBeCalledWith(
          `SAML-EXT-${expectedAuthnRequestID}`,
          expect.any(Function)
        );
        expect(mockedCallback).toBeCalledWith(
          new Error(
            `SAML#ExtendedRedisCacheProvider: remove() error ${expectedDelError}`
          )
        );
        resolve();
      }, 100);
    });
  });
});

describe("CustomSamlClient#generateAuthorizeRequest", () => {
  const mockCallback = jest.fn();
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("should generateAuthorizeRequest call super generateAuthorizeRequest if tamperAuthorizeRequest is not provided", () => {
    const req = mockReq();
    const expectedXML = "<xml></xml>";
    mockWrapCallback.mockImplementation(callback => {
      callback(null, expectedXML);
    });
    const customSamlClient = new CustomSamlClient(
      { validateInResponseTo: true },
      redisCacheProvider
    );
    customSamlClient.generateAuthorizeRequest(req, false, mockCallback);
    expect(mockCallback).toBeCalledWith(null, expectedXML);
  });

  it("should generateAuthorizeRequest save the SAML Request if tamperAuthorizeRequest is not provided", async () => {
    const mockAuthReqTampener = jest.fn().mockImplementation(xml => {
      return fromEither(right(xml));
    });
    mockWrapCallback.mockImplementation(callback => {
      callback(null, SAMLRequest);
    });
    const req = mockReq();
    mockSet.mockImplementation((_, __, ___, ____, callback) => {
      callback(null, "OK");
    });
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true
      },
      redisCacheProvider,
      mockAuthReqTampener
    );
    customSamlClient.generateAuthorizeRequest(req, false, mockCallback);
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest);
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise(resolve => {
      setTimeout(() => {
        expect(mockSet).toBeCalled();
        expect(mockCallback).toBeCalledWith(null, SAMLRequest);
        resolve();
      }, 100);
    });
  });

  it("should generateAuthorizeRequest return an error if tamperAuthorizeRequest fail", async () => {
    const expectedTamperError = new Error("tamperAuthorizeRequest Error");
    const mockAuthReqTampener = jest.fn().mockImplementation(_ => {
      return fromEither(left(expectedTamperError));
    });
    mockWrapCallback.mockImplementation(callback => {
      callback(null, SAMLRequest);
    });
    const req = mockReq();
    mockSet.mockImplementation((_, __, ___, ____, callback) => {
      callback(null, "OK");
    });
    const customSamlClient = new CustomSamlClient(
      {
        entryPoint: "https://localhost:3000/acs",
        idpIssuer: "https://localhost:8080",
        issuer: "https://localhost:3000",
        validateInResponseTo: true
      },
      redisCacheProvider,
      mockAuthReqTampener
    );
    customSamlClient.generateAuthorizeRequest(req, false, mockCallback);
    expect(mockAuthReqTampener).toBeCalledWith(SAMLRequest);
    // Before checking the execution of the callback we must await that the TaskEither execution is completed.
    await new Promise(resolve => {
      setTimeout(() => {
        expect(mockSet).not.toBeCalled();
        expect(mockCallback).toBeCalledWith(expectedTamperError);
        resolve();
      }, 100);
    });
  });
});
