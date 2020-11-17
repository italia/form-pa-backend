import { right } from "fp-ts/lib/Either";
import { isSome, tryCatch } from "fp-ts/lib/Option";
import { fromEither } from "fp-ts/lib/TaskEither";
import { SamlConfig } from "passport-saml";
import { DOMParser } from "xmldom";
import { EventTracker } from "../../index";
import {
  getSamlAssertion,
  getSamlResponse,
  samlEncryptedAssertion,
  samlRequest,
  samlResponseCIE
} from "../__mocks__/saml";
import { StrictResponseValidationOptions } from "../middleware";
import { getPreValidateResponse, getXmlFromSamlResponse } from "../saml";
import * as saml from "../saml";

const samlConfig: SamlConfig = ({
  attributes: {
    attributes: {
      attributes: ["name", "fiscalNumber", "familyName", "mobilePhone", "email"]
    }
  },
  authnContext: "https://www.spid.gov.it/SpidL2",
  callbackUrl: "https://app-backend.dev.io.italia.it/assertionConsumerService",
  issuer: "https://app-backend.dev.io.italia.it"
} as unknown) as SamlConfig;

const aResponseSignedWithHMAC = getSamlResponse({
  signatureMethod: "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
});
const aResponseWithOneAssertionSignedWithHMAC = getSamlResponse({
  customAssertion: getSamlAssertion(
    0,
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
  )
});
const aResponseSignedWithHMACWithOneAssertionSignedWithHMAC = getSamlResponse({
  customAssertion: getSamlAssertion(
    0,
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
  ),
  signatureMethod: "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
});

describe("getXmlFromSamlResponse", () => {
  it("should parse a well formatted response body", () => {
    const expectedSAMLResponse = "<xml>Response</xml>";
    const responseBody = {
      SAMLResponse: Buffer.from(expectedSAMLResponse).toString("base64")
    };
    const responseDocument = getXmlFromSamlResponse(responseBody);
    expect(isSome(responseDocument)).toBeTruthy();
  });
});

// tslint:disable-next-line: no-big-function
describe("preValidateResponse", () => {
  const mockCallback = jest.fn();
  const mockGetXmlFromSamlResponse = jest.spyOn(saml, "getXmlFromSamlResponse");
  const mockGet = jest.fn();
  const mockRedisCacheProvider = {
    get: mockGet,
    remove: jest.fn(),
    save: jest.fn()
  };
  const mockBody = "MOCKED BODY";
  const mockTestIdpIssuer = "http://localhost:8080";

  const mockEventTracker = jest.fn() as EventTracker;

  const expectedDesynResponseValueMs = 2000;

  const expectedGenericEventName = "spid.error.generic";
  const expectedSignatureErrorName = "spid.error.signature";

  const asyncExpectOnCallback = (callback: jest.Mock, error?: Error) =>
    new Promise(resolve => {
      setTimeout(() => {
        error
          ? expect(callback).toBeCalledWith(error)
          : expect(callback).toBeCalledWith(null, true, expect.any(String));
        resolve();
      }, 100);
    });

  beforeEach(() => {
    jest.resetAllMocks();
    mockGet.mockImplementation(() => {
      return fromEither(
        right({
          RequestXML: samlRequest,
          createdAt: "2020-02-26T07:27:42Z",
          idpIssuer: mockTestIdpIssuer
        })
      );
    });
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  it("should preValidate fail when saml Response has multiple Assertion elements", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ customAssertion: getSamlAssertion().repeat(2) })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    const expectedError = new Error(
      "SAML Response must have only one Assertion element"
    );
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });

  it("should preValidate fail when saml Response has EncryptedAssertion element", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ customAssertion: samlEncryptedAssertion })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    const expectedError = new Error("EncryptedAssertion element is forbidden");
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });

  it("should preValidate fail when saml Response has multiple Response elements", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(getSamlResponse().repeat(2))
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    const expectedError = new Error(
      "SAML Response must have only one Response element"
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });

  it("should preValidate succeded with a valid saml Response", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() => new DOMParser().parseFromString(getSamlResponse()))
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate succeded and send an Event on valid Response with missing Signature", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ hasResponseSignature: false })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        idpIssuer: mockTestIdpIssuer,
        message: expect.any(String)
      },
      name: expectedSignatureErrorName,
      type: "INFO"
    });
  });

  it("should preValidate succeed if timers are desynchronized and acceptedClockSkewMs is disabled", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ clockSkewMs: expectedDesynResponseValueMs })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      { ...samlConfig, acceptedClockSkewMs: -1 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate succeed if timers desync is less than acceptedClockSkewMs", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ clockSkewMs: expectedDesynResponseValueMs })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      { ...samlConfig, acceptedClockSkewMs: 2000 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(mockCallback);
  });

  it("should preValidate fail if timer desync exceeds acceptedClockSkewMs", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({ clockSkewMs: expectedDesynResponseValueMs })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption)(
      {
        ...samlConfig,
        acceptedClockSkewMs: expectedDesynResponseValueMs - 100
      },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    await asyncExpectOnCallback(
      mockCallback,
      new Error("IssueInstant must be in the past")
    );
  });

  it.each`
    title                                                                                            | response
    ${"uses HMAC as signature algorithm"}                                                            | ${aResponseSignedWithHMAC}
    ${"has an assertion that uses HMAC as signature algorithm"}                                      | ${aResponseWithOneAssertionSignedWithHMAC}
    ${"uses HMAC as signature algorithm and has an assertion that uses HMAC as signature algorithm"} | ${aResponseSignedWithHMACWithOneAssertionSignedWithHMAC}
  `(
    "should preValidate fail when saml Response $title",
    async ({ response }) => {
      mockGetXmlFromSamlResponse.mockImplementation(() =>
        tryCatch(() => new DOMParser().parseFromString(response))
      );
      const strictValidationOption: StrictResponseValidationOptions = {
        mockTestIdpIssuer: true
      };
      getPreValidateResponse(strictValidationOption, mockEventTracker)(
        { ...samlConfig, acceptedClockSkewMs: 0 },
        mockBody,
        mockRedisCacheProvider,
        undefined,
        mockCallback
      );
      expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
      const expectedError = new Error("HMAC Signature is forbidden");
      await asyncExpectOnCallback(mockCallback, expectedError);
      expect(mockEventTracker).toBeCalledWith({
        data: {
          message: expectedError.message
        },
        name: expectedGenericEventName,
        type: "ERROR"
      });
    }
  );

  describe("preValidateResponse with CIE saml Response", () => {
    beforeEach(() => {
      jest.resetAllMocks();
    });

    it("should preValidate succeded with a valid CIE saml Response", async () => {
      mockGetXmlFromSamlResponse.mockImplementation(() =>
        tryCatch(() => new DOMParser().parseFromString(samlResponseCIE))
      );
      // tslint:disable-next-line: no-identical-functions
      mockGet.mockImplementation(() => {
        return fromEither(
          right({
            RequestXML: samlRequest,
            createdAt: "2020-02-26T07:27:42Z",
            idpIssuer:
              "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO"
          })
        );
      });
      getPreValidateResponse()(
        samlConfig,
        mockBody,
        mockRedisCacheProvider,
        undefined,
        mockCallback
      );
      expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
      await asyncExpectOnCallback(mockCallback);
    });
  });

  it("should preValidate fail when saml Response uses HMAC as signature algorithm", async () => {
    mockGetXmlFromSamlResponse.mockImplementation(() =>
      tryCatch(() =>
        new DOMParser().parseFromString(
          getSamlResponse({
            signatureMethod: "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
          })
        )
      )
    );
    const strictValidationOption: StrictResponseValidationOptions = {
      mockTestIdpIssuer: true
    };
    getPreValidateResponse(strictValidationOption, mockEventTracker)(
      { ...samlConfig, acceptedClockSkewMs: 0 },
      mockBody,
      mockRedisCacheProvider,
      undefined,
      mockCallback
    );
    expect(mockGetXmlFromSamlResponse).toBeCalledWith(mockBody);
    const expectedError = new Error("HMAC Signature is forbidden");
    await asyncExpectOnCallback(mockCallback, expectedError);
    expect(mockEventTracker).toBeCalledWith({
      data: {
        message: expectedError.message
      },
      name: expectedGenericEventName,
      type: "ERROR"
    });
  });
});
