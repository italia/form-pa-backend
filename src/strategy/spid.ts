import * as express from "express";
import { TaskEither } from "fp-ts/lib/TaskEither";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest
} from "passport-saml";
import { Strategy as SamlStrategy } from "passport-saml";
import { RedisClient } from "redis";

// tslint:disable-next-line: no-submodule-imports
import { MultiSamlConfig } from "passport-saml/multiSamlStrategy";

import { Second } from "italia-ts-commons/lib/units";
import * as requestIp from "request-ip";
import { DoneCallbackT } from "..";
import {
  getExtendedRedisCacheProvider,
  IExtendedCacheProvider,
  noopCacheProvider
} from "./redis_cache_provider";
import { CustomSamlClient } from "./saml_client";

export type XmlTamperer = (xml: string) => TaskEither<Error, string>;

export type PreValidateResponseDoneCallbackT = (
  request: string,
  response: string
) => void;

export type PreValidateResponseT = (
  samlConfig: SamlConfig,
  body: unknown,
  extendedRedisCacheProvider: IExtendedCacheProvider,
  doneCb: PreValidateResponseDoneCallbackT | undefined,
  // tslint:disable-next-line: bool-param-default
  callback: (
    err: Error | null,
    // tslint:disable-next-line: bool-param-default
    isValid?: boolean,
    InResponseTo?: string
  ) => void
) => void;

export class SpidStrategy extends SamlStrategy {
  private extendedRedisCacheProvider: IExtendedCacheProvider;

  constructor(
    private options: SamlConfig,
    private getSamlOptions: MultiSamlConfig["getSamlOptions"],
    verify: VerifyWithRequest | VerifyWithoutRequest,
    private redisClient: RedisClient,
    private tamperAuthorizeRequest?: XmlTamperer,
    private tamperMetadata?: XmlTamperer,
    private preValidateResponse?: PreValidateResponseT,
    private doneCb?: DoneCallbackT
  ) {
    super(options, verify);
    if (!options.requestIdExpirationPeriodMs) {
      // 15 minutes
      options.requestIdExpirationPeriodMs = 15 * 60 * 1000;
    }

    // use our custom cache provider
    this.extendedRedisCacheProvider = getExtendedRedisCacheProvider(
      this.redisClient,
      Math.floor(options.requestIdExpirationPeriodMs / 1000) as Second
    );

    // bypass passport-saml cache provider
    options.cacheProvider = noopCacheProvider();
  }

  public authenticate(
    req: express.Request,
    options: AuthenticateOptions | AuthorizeOptions
  ): void {
    this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      const samlService = new CustomSamlClient(
        {
          ...this.options,
          ...samlOptions
        },
        this.extendedRedisCacheProvider,
        this.tamperAuthorizeRequest,
        this.preValidateResponse,
        (...args) =>
          this.doneCb
            ? this.doneCb(requestIp.getClientIp(req), ...args)
            : undefined
      );
      // we clone the original strategy to avoid race conditions
      // see https://github.com/bergie/passport-saml/pull/426/files
      const strategy = Object.setPrototypeOf(
        {
          ...this,
          _saml: samlService
        },
        this
      );
      super.authenticate.call(strategy, req, options);
    });
  }

  public logout(
    req: express.Request,
    callback: (err: Error | null, url?: string) => void
  ): void {
    this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      const samlService = new CustomSamlClient(
        {
          ...this.options,
          ...samlOptions
        },
        this.extendedRedisCacheProvider
      );
      // we clone the original strategy to avoid race conditions
      // see https://github.com/bergie/passport-saml/pull/426/files
      const strategy = Object.setPrototypeOf(
        {
          ...this,
          _saml: samlService
        },
        this
      );
      super.logout.call(strategy, req, callback);
    });
  }

  public generateServiceProviderMetadataAsync(
    req: express.Request,
    decryptionCert: string | null,
    signingCert: string | null,
    callback: (err: Error | null, metadata?: string) => void
  ): void {
    return this.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }
      const samlService = new CustomSamlClient(
        {
          ...this.options,
          ...samlOptions
        },
        this.extendedRedisCacheProvider
      );

      // we clone the original strategy to avoid race conditions
      // see https://github.com/bergie/passport-saml/pull/426/files
      const strategy = Object.setPrototypeOf(
        {
          ...this,
          _saml: samlService
        },
        this
      );

      const originalXml = super.generateServiceProviderMetadata.call(
        strategy,
        decryptionCert,
        signingCert
      );

      return this.tamperMetadata
        ? // Tamper the generated XML for service provider metadata
          this.tamperMetadata(originalXml)
            .fold(
              e => callback(e),
              tamperedXml => callback(null, tamperedXml)
            )
            .run()
        : callback(null, originalXml);
    });
  }
}
