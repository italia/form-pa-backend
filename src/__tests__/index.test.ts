import * as express from "express";
import { left, right } from "fp-ts/lib/Either";
import { fromEither } from "fp-ts/lib/TaskEither";
import { ResponsePermanentRedirect } from "italia-ts-commons/lib/responses";
import { createMockRedis } from "mock-redis-client";
import { RedisClient } from "redis";
import {
  IApplicationConfig,
  IServiceProviderConfig,
  SamlConfig,
  withSpid
} from "../";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import * as metadata from "../utils/metadata";
import { getSpidStrategyOption } from "../utils/middleware";

import {
  mockCIEIdpMetadata,
  mockIdpMetadata,
  mockTestenvIdpMetadata
} from "../__mocks__/metadata";

const mockFetchIdpsMetadata = jest.spyOn(metadata, "fetchIdpsMetadata");

// saml configuration vars
const samlCert = `
-----BEGIN CERTIFICATE-----
MIIDczCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBTMQswCQYDVQQGEwJpdDEN
MAsGA1UECAwEUm9tZTEUMBIGA1UECgwLYWdpZC5nb3YuaXQxHzAdBgNVBAMMFmh0
dHBzOi8vaXRhbGlhLWJhY2tlbmQwHhcNMTcxMDI2MTAzNTQwWhcNMTgxMDI2MTAz
NTQwWjBTMQswCQYDVQQGEwJpdDENMAsGA1UECAwEUm9tZTEUMBIGA1UECgwLYWdp
ZC5nb3YuaXQxHzAdBgNVBAMMFmh0dHBzOi8vaXRhbGlhLWJhY2tlbmQwggEjMA0G
CSqGSIb3DQEBAQUAA4IBEAAwggELAoIBAgCXozdOvdlQhX2zyOvnpZJZWyhjmiRq
kBW7jkZHcmFRceeoVkXGn4bAFGGcqESFMVmaigTEm1c6gJpRojo75smqyWxngEk1
XLctn1+Qhb5SCbd2oHh0oLE5jpHyrxfxw8V+N2Hty26GavJE7i9jORbjeQCMkbgg
t0FahmlmaZr20akK8wNGMHDcpnMslJPxHl6uKxjAfe6sbNqjWxfcnirm05Jh5gYN
T4vkwC1vx6AZpS2G9pxOV1q5GapuvUBqwNu+EH1ufMRRXvu0+GtJ4WtsErOakSF4
KMezrMqKCrVPoK5SGxQMD/kwEQ8HfUPpim3cdi3RVmqQjsi/on6DMn/xTQIDAQAB
o1AwTjAdBgNVHQ4EFgQULOauBsRgsAudzlxzwEXYXd4uPyIwHwYDVR0jBBgwFoAU
LOauBsRgsAudzlxzwEXYXd4uPyIwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0F
AAOCAQIAQOT5nIiAefn8FAWiVYu2uEsHpxUQ/lKWn1Trnj7MyQW3QA/jNaJHL/Ep
szJ5GONOE0lVEG1on35kQOWR7qFWYhH9Llb8EAAAb5tbnCiA+WIx4wjRTE3CNLul
L8MoscacIc/rqWf5WygZQcPDX1yVxmK4F3YGG2qDTD3fr4wPweYHxn95JidTwzW8
Jv46ajSBvFJ95CoCYL3BUHaxPIlYkGbJFjQhuoxo2XM4iT6KFD4IGmdssS4NFgW+
OM+P8UsrYi2KZuyzSrHq5c0GJz0UzSs8cIDC/CPEajx2Uy+7TABwR4d20Hyo6WIm
IFJiDanROwzoG0YNd8aCWE8ZM2y81Ww=
-----END CERTIFICATE-----
`;

const samlKey = `
-----BEGIN PRIVATE KEY-----
MIIEwQIBADANBgkqhkiG9w0BAQEFAASCBKswggSnAgEAAoIBAgCXozdOvdlQhX2z
yOvnpZJZWyhjmiRqkBW7jkZHcmFRceeoVkXGn4bAFGGcqESFMVmaigTEm1c6gJpR
ojo75smqyWxngEk1XLctn1+Qhb5SCbd2oHh0oLE5jpHyrxfxw8V+N2Hty26GavJE
7i9jORbjeQCMkbggt0FahmlmaZr20akK8wNGMHDcpnMslJPxHl6uKxjAfe6sbNqj
Wxfcnirm05Jh5gYNT4vkwC1vx6AZpS2G9pxOV1q5GapuvUBqwNu+EH1ufMRRXvu0
+GtJ4WtsErOakSF4KMezrMqKCrVPoK5SGxQMD/kwEQ8HfUPpim3cdi3RVmqQjsi/
on6DMn/xTQIDAQABAoIBAWo61Yw8Q/m9CwrgPyPRQm2HBwx/9/MPbaovSdzTrIm6
Gmg7yDYVm/kETj3JQ/drUzKIbj6t9LXvUizOUa2VSMJ0yZTYsnDHuywi8nf0uhgO
5pAca0aJLJ792hEByOx+EeUSN3C3i35vfbn8gwYoAHjrVA8mJrAEsawRbdVpNj6j
IWAKTmsZK0YLdcNzWshSYW9wkJNykeXHUgKk2YzGUIacMgC+fF3v3xL82xk+eLez
dP5wlrzkPz8JKHMIomF5j/VLuggSZx0XdQRvZrkeQUbJqRy2iXa43B+OlEiNvd2Q
0AiXur/MhvID+Ni/hBIoeIDyvvoBoiCTZbVvyRnBds8BAoGBDIfqHTTcfXlzfipt
4+idRuuzzhIXzQOcB0+8ywqmgtE4g9EykC7fEcynOavv08rOSNSbYhjLX24xUSrd
19lckZIvH5U9nJxnyfwrMGrorCA2uPtck8N9sTB5UWif31w/eDVMv30jRUyMel7l
tp96zxcPThT1O3N4zM2Otk5q2DvFAoGBDBngF4G9dJ5a511dyYco2agMJTvJLIqn
kKw24KOTqZ5BZKyIea4yCy9cRmNN84ccOy3jBuzSFLNJMYqdDCzH46u0I4anft83
aqnVa4jOwjZXoV9JCdFh3zKJUgPU4CW0MaTb30n3U4BAOgkHzRFt55tGT6xRU1J+
jX5s03BFfQ/pAoGBCsRqtUfrweEvDRT2MeR56Cu153cCfoYAdwPcDHeNVlDih9mk
4eF0ib3ZXyPPQqQ8FrahAWyeq9Rqif0UfFloQiljVncNZtm6EQQeNE9YuDZB7zcF
eG59PViSlhIZdXq1itv5o3yqZux8tNV/+ykUBIgi/YvioH/7J7flTd8Zzc2lAoGB
CqdVNRzSETPBUGRQx7Yo7scWOkmSaZaAw8v6XHdm7zQW2m1Tkd0czeAaWxXecQKI
hkl10Ij6w6K8U9N3RFrAeN6YL5bDK92VSmDPNmcxsKZrK/VZtj0S74/sebpJ1jUb
mYFM2h6ikm8dHHsK1S39FqULl+VbjAHazPN7GAOGCf7RAoGBAc0J9j+MHYm4M18K
AW2UB26qvdc8PSXE6i4YQAsg2RBgtf6u4jVAQ8a8OA4vnGG9VIrR0bD/hFTfczg/
ZbWGZ+42VH2eDGouiadR4rWzJNQKjWd98Y5PzxdEjd6nneJ68iNqGbKOT6jXu8qj
nCnxP/vK5rgVHU3nQfq+e/B6FVWZ
-----END PRIVATE KEY-----
`;

const spidTestEnvUrl = "https://localhost:8088";
const IDPMetadataUrl =
  "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml";
const spidCieUrl =
  "https://idserver.servizicie.interno.gov.it:8443/idp/shibboleth";

const expectedLoginPath = "/login";
const expectedSloPath = "/logout";
const expectedAssertionConsumerServicePath = "/assertionConsumerService";
const metadataPath = "/metadata";

const appConfig: IApplicationConfig = {
  assertionConsumerServicePath: expectedAssertionConsumerServicePath,
  clientErrorRedirectionUrl: "/error",
  clientLoginRedirectionUrl: "/success",
  loginPath: expectedLoginPath,
  metadataPath,
  sloPath: expectedSloPath
};

const samlConfig: SamlConfig = {
  RACComparison: "minimum",
  acceptedClockSkewMs: 0,
  attributeConsumingServiceIndex: "0",
  authnContext: "https://www.spid.gov.it/SpidL1",
  callbackUrl: "http://localhost:3000" + appConfig.assertionConsumerServicePath,
  // decryptionPvk: fs.readFileSync("./certs/key.pem", "utf-8"),
  identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  issuer: "https://spid.agid.gov.it/cd",
  logoutCallbackUrl: "http://localhost:3000/slo",
  privateCert: samlKey,
  validateInResponseTo: true
};

const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl,
  organization: {
    URL: "https://example.com",
    displayName: "Organization display name",
    name: "Organization name"
  },
  publicCert: samlCert,
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
  spidCieUrl,
  spidTestEnvUrl,
  strictResponseValidation: {
    "http://localhost:8080": true
  }
};

// tslint:disable-next-line: no-any
const mockRedisClient: RedisClient = (createMockRedis() as any).createClient();

describe("io-spid-commons withSpid", () => {
  it("shoud idpMetadataRefresher refresh idps metadata from remote url", async () => {
    const app = express();
    mockFetchIdpsMetadata.mockImplementation(() =>
      fromEither(
        left<Error, Record<string, IDPEntityDescriptor>>(new Error("Error."))
      )
    );
    const spid = await withSpid({
      appConfig,
      samlConfig,
      serviceProviderConfig,
      // tslint:disable-next-line: object-literal-sort-keys
      redisClient: mockRedisClient,
      app,
      acs: async () => ResponsePermanentRedirect({ href: "/success?acs" }),
      logout: async () => ResponsePermanentRedirect({ href: "/success?logout" })
    }).run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(3);
    const emptySpidStrategyOption = getSpidStrategyOption(spid.app);
    expect(emptySpidStrategyOption).toHaveProperty("idp", {});

    jest.resetAllMocks();

    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(mockIdpMetadata)
      );
    });
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(mockCIEIdpMetadata)
      );
    });
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(
          mockTestenvIdpMetadata
        )
      );
    });
    await spid.idpMetadataRefresher().run();
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      1,
      IDPMetadataUrl,
      expect.any(Object)
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      2,
      spidCieUrl,
      expect.any(Object)
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      3,
      `${spidTestEnvUrl}/metadata`,
      expect.any(Object)
    );
    const spidStrategyOption = getSpidStrategyOption(spid.app);
    expect(spidStrategyOption).toHaveProperty("idp", {
      ...mockIdpMetadata,
      ...mockCIEIdpMetadata,
      ...mockTestenvIdpMetadata
    });
  });
});
