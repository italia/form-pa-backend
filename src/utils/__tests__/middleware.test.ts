// tslint:disable-next-line: ordered-imports
import { left, right } from "fp-ts/lib/Either";
import { fromEither } from "fp-ts/lib/TaskEither";
import { SamlConfig } from "passport-saml";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../../config";
import { IDPEntityDescriptor } from "../../types/IDPEntityDescriptor";
import * as metadata from "../metadata";
import {
  getSpidStrategyOptionsUpdater,
  IServiceProviderConfig
} from "../middleware";

import {
  mockCIEIdpMetadata,
  mockIdpMetadata,
  mockTestenvIdpMetadata
} from "../../__mocks__/metadata";

const mockFetchIdpsMetadata = jest.spyOn(metadata, "fetchIdpsMetadata");

const idpMetadataUrl = "http://ipd.metadata.example/metadata.xml";
const cieMetadataUrl =
  "https://idserver.servizicie.interno.gov.it:8443/idp/shibboleth";
const spidTestEnvUrl = "https://spid-testenv2:8088";

const serviceProviderConfig: IServiceProviderConfig = {
  IDPMetadataUrl: idpMetadataUrl,
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
  spidCieUrl: cieMetadataUrl,
  spidTestEnvUrl
};
const expectedSamlConfig: SamlConfig = {
  callbackUrl: "http://localhost:3000/callback",
  entryPoint: "http://localhost:3000/acs",
  forceAuthn: true
};

describe("getSpidStrategyOptionsUpdater", () => {
  const expectedSPProperty = {
    ...expectedSamlConfig,
    attributes: {
      attributes: serviceProviderConfig.requiredAttributes,
      name: "Required attributes"
    },
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    organization: serviceProviderConfig.organization,
    signatureAlgorithm: "sha256"
  };

  beforeEach(() => {
    jest.resetAllMocks();
  });
  afterAll(() => {
    jest.restoreAllMocks();
  });
  it("should returns updated spid options from remote idps metadata", async () => {
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

    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(3);
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      1,
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      2,
      cieMetadataUrl,
      CIE_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      3,
      `${spidTestEnvUrl}/metadata`,
      {
        [spidTestEnvUrl]: "xx_testenv2"
      }
    );
    expect(updatedSpidStrategyOption).toHaveProperty("sp", expectedSPProperty);
    expect(updatedSpidStrategyOption).toHaveProperty("idp", {
      ...mockIdpMetadata,
      ...mockCIEIdpMetadata,
      ...mockTestenvIdpMetadata
    });
  });

  it("should returns an error if fetch of remote idp metadata fail", async () => {
    const expectedFetchError = new Error("fetch Error");
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        left<Error, Record<string, IDPEntityDescriptor>>(expectedFetchError)
      );
    });
    // tslint:disable-next-line: no-identical-functions
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(mockCIEIdpMetadata)
      );
    });
    // tslint:disable-next-line: no-identical-functions
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(
          mockTestenvIdpMetadata
        )
      );
    });
    const updatedSpidStrategyOption = await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfig
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(3);
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      1,
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      2,
      cieMetadataUrl,
      CIE_IDP_IDENTIFIERS
    );
    expect(mockFetchIdpsMetadata).toHaveBeenNthCalledWith(
      3,
      `${spidTestEnvUrl}/metadata`,
      {
        [spidTestEnvUrl]: "xx_testenv2"
      }
    );
    expect(updatedSpidStrategyOption).toHaveProperty("sp", expectedSPProperty);
    expect(updatedSpidStrategyOption).toHaveProperty("idp", {
      ...mockCIEIdpMetadata,
      ...mockTestenvIdpMetadata
    });
  });

  it("should call fetchIdpsMetadata only one time if are missing CIE and TestEnv urls", async () => {
    const serviceProviderConfigWithoutOptional: IServiceProviderConfig = {
      IDPMetadataUrl: idpMetadataUrl,
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
      }
    };
    // tslint:disable-next-line: no-identical-functions
    mockFetchIdpsMetadata.mockImplementationOnce(() => {
      return fromEither(
        right<Error, Record<string, IDPEntityDescriptor>>(mockIdpMetadata)
      );
    });
    await getSpidStrategyOptionsUpdater(
      expectedSamlConfig,
      serviceProviderConfigWithoutOptional
    )().run();
    expect(mockFetchIdpsMetadata).toBeCalledTimes(1);
    expect(mockFetchIdpsMetadata).toBeCalledWith(
      idpMetadataUrl,
      SPID_IDP_IDENTIFIERS
    );
  });
});
