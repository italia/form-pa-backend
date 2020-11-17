import { isLeft, isRight, left } from "fp-ts/lib/Either";
import { NonEmptyArray } from "fp-ts/lib/NonEmptyArray";
import * as nock from "nock";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../../config";
import cieIdpMetadata from "../__mocks__/cie-idp-metadata";
import idpsMetadata from "../__mocks__/idps-metatata";
import testenvIdpMetadata from "../__mocks__/testenv-idp-metadata";
import { fetchIdpsMetadata } from "../metadata";

const mockedIdpsRegistryHost = "https://mocked.registry.net";
const expectedTestenvEntityId = "https://spid-testenv.dev.io.italia.it";

describe("fetchIdpsMetadata", () => {
  it("should reject if the IdP metadata are fetched from a wrong path", async () => {
    const notExistingPath = "/not-existing-path";
    nock(mockedIdpsRegistryHost)
      .get(notExistingPath)
      .reply(404);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + notExistingPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns no useful data", async () => {
    const wrongIdpMetadataPath = "/wrong-path";
    nock(mockedIdpsRegistryHost)
      .get(wrongIdpMetadataPath)
      .reply(200, { property: "same value" });
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + wrongIdpMetadataPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should reject an error if the fetch of IdP metadata returns an unparsable response", async () => {
    const wrongIdpMetadataPath = "/wrong-path";
    nock(mockedIdpsRegistryHost)
      .get(wrongIdpMetadataPath)
      .reply(200, undefined);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + wrongIdpMetadataPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isLeft(result)).toBeTruthy();
    expect(result.value).toEqual(expect.any(Error));
  });

  it("should resolve with the fetched IdP options", async () => {
    const validIdpMetadataPath = "/correct-path";
    nock(mockedIdpsRegistryHost)
      .get(validIdpMetadataPath)
      .reply(200, idpsMetadata);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + validIdpMetadataPath,
      SPID_IDP_IDENTIFIERS
    ).run();
    expect(isRight(result)).toBeTruthy();
  });

  it("should resolve with the fetched CIE IdP options", async () => {
    const validCieMetadataPath = "/mocked-cie-path";
    nock(mockedIdpsRegistryHost)
      .get(validCieMetadataPath)
      .reply(200, cieIdpMetadata);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + validCieMetadataPath,
      CIE_IDP_IDENTIFIERS
    ).run();
    expect(isRight(result)).toBeTruthy();
    expect(result.value).toHaveProperty("xx_servizicie_test", {
      cert: expect.any(NonEmptyArray),
      entityID:
        "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO",
      entryPoint:
        "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/Redirect/SSO",
      logoutUrl: ""
    });
  });

  it("should resolve with the fetched TestEnv IdP options", async () => {
    const validTestenvMetadataPath = "/mocked-testenv-path";
    nock(mockedIdpsRegistryHost)
      .get(validTestenvMetadataPath)
      .reply(200, testenvIdpMetadata);
    const result = await fetchIdpsMetadata(
      mockedIdpsRegistryHost + validTestenvMetadataPath,
      {
        [expectedTestenvEntityId]: "xx_testenv2"
      }
    ).run();
    expect(isRight(result)).toBeTruthy();
    expect(result.value).toHaveProperty("xx_testenv2", {
      cert: expect.any(NonEmptyArray),
      entityID: expectedTestenvEntityId,
      entryPoint: "https://spid-testenv.dev.io.italia.it/sso",
      logoutUrl: "https://spid-testenv.dev.io.italia.it/slo"
    });
  });
});
