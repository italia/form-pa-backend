import {
  SamlConfig,
  VerifyWithRequest,
  VerifyWithoutRequest
} from "passport-saml";

import * as express from "express";

declare module "passport-saml" {
  export class SAML {
    private options: unknown;
    constructor(config: SamlConfig);

    validatePostResponse(
      body: { SAMLResponse: string },
      callback: (err: Error, profile?: unknown, loggedOut?: boolean) => void
    ): void;

    generateAuthorizeRequest(
      req: express.Request,
      isPassive: boolean,
      callback: (err: Error, xml?: string) => void
    ): void;
  }
}
