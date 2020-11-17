// tslint:disable: no-any
import * as express from "express";
import { SamlConfig } from "passport-saml";
// tslint:disable-next-line: no-var-requires
const OriginalSAML = require("passport-saml").SAML;

export const mockWrapCallback = jest.fn();

// tslint:disable: max-classes-per-file
export class SAML {
  public options: any;
  public cacheProvider: any;

  private initialize = OriginalSAML.prototype.initialize;
  constructor(samlConfig: SamlConfig) {
    // tslint:disable-next-line: no-string-literal
    this.options = this.initialize(samlConfig);
    this.cacheProvider = this.options.cacheProvider;
  }

  public validatePostResponse(
    body: { SAMLResponse: string },
    callback: (
      err: Error | null,
      profile?: unknown,
      // tslint:disable-next-line: bool-param-default
      loggedOut?: boolean
    ) => void
  ): void {
    callback(null, {}, false);
  }

  public generateAuthorizeRequest(
    req: express.Request,
    isPassive: boolean,
    callback: (err: Error | null, xml?: string) => void
  ): void {
    mockWrapCallback(callback);
  }
}

export class Strategy {
  constructor() {
    // tslint:disable-next-line: no-console
    console.log("Mock Strategy: constructor was called");
  }
}
