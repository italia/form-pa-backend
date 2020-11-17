import { fromOption, parseJSON, toError } from "fp-ts/lib/Either";
import { fromNullable } from "fp-ts/lib/Option";
import { fromEither, TaskEither, taskify } from "fp-ts/lib/TaskEither";
import * as t from "io-ts";
import { UTCISODateFromString } from "italia-ts-commons/lib/dates";
import { readableReport } from "italia-ts-commons/lib/reporters";
import { Second } from "italia-ts-commons/lib/units";
import { CacheProvider, SamlConfig } from "passport-saml";
import * as redis from "redis";
import { getIDFromRequest } from "../utils/saml";

export type SAMLRequestCacheItem = t.TypeOf<typeof SAMLRequestCacheItem>;
const SAMLRequestCacheItem = t.interface({
  RequestXML: t.string,
  createdAt: UTCISODateFromString,
  idpIssuer: t.string,
  userData: t.union([t.object, t.undefined])
});

export interface IExtendedCacheProvider {
  save: (
    RequestXML: string,
    samlConfig: SamlConfig,
    userData?: object
  ) => TaskEither<Error, SAMLRequestCacheItem>;
  get: (AuthnRequestID: string) => TaskEither<Error, SAMLRequestCacheItem>;
  remove: (AuthnRequestID: string) => TaskEither<Error, string>;
}

// those methods must never fail since there's
// practically no error handling in passport-saml
// (a very bad lot of spaghetti code)
export const noopCacheProvider = (): CacheProvider => {
  return {
    // saves the key with the optional value
    // invokes the callback with the value saved
    save(_, value, callback): void {
      const v = {
        createdAt: new Date(),
        value
      };
      callback(null, v);
    },
    // invokes 'callback' and passes the value if found, null otherwise
    get(_, callback): void {
      callback(null, {});
    },
    // removes the key from the cache, invokes `callback` with the
    // key removed, null if no key is removed
    remove(key, callback): void {
      callback(null, key);
    }
  };
};

export const getExtendedRedisCacheProvider = (
  redisClient: redis.RedisClient,
  // 1 hour by default
  keyExpirationPeriodSeconds: Second = 3600 as Second,
  keyPrefix: string = "SAML-EXT-"
): IExtendedCacheProvider => {
  return {
    save(
      RequestXML: string,
      samlConfig: SamlConfig,
      userData?: object
    ): TaskEither<Error, SAMLRequestCacheItem> {
      return fromEither(
        fromOption(
          new Error(`SAML#ExtendedRedisCacheProvider: missing AuthnRequest ID`)
        )(getIDFromRequest(RequestXML))
      )
        .chain(AuthnRequestID =>
          fromEither(
            fromOption(new Error("Missing idpIssuer inside configuration"))(
              fromNullable(samlConfig.idpIssuer)
            )
          ).map(idpIssuer => ({ idpIssuer, AuthnRequestID }))
        )
        .chain(_ => {
          const v: SAMLRequestCacheItem = {
            RequestXML,
            createdAt: new Date(),
            idpIssuer: _.idpIssuer,
            userData
          };
          return taskify(
            (
              key: string,
              data: string,
              flag: "EX",
              expiration: number,
              callback: (err: Error | null, value: unknown) => void
            ) => redisClient.set(key, data, flag, expiration, callback)
          )(
            `${keyPrefix}${_.AuthnRequestID}`,
            JSON.stringify(v),
            "EX",
            keyExpirationPeriodSeconds
          )
            .mapLeft(
              err =>
                new Error(`SAML#ExtendedRedisCacheProvider: set() error ${err}`)
            )
            .map(() => v);
        });
    },
    get(AuthnRequestID: string): TaskEither<Error, SAMLRequestCacheItem> {
      return taskify(
        (key: string, callback: (e: Error | null, value?: string) => void) => {
          redisClient.get(key, callback);
        }
      )(`${keyPrefix}${AuthnRequestID}`)
        .mapLeft(
          err =>
            new Error(`SAML#ExtendedRedisCacheProvider: get() error ${err}`)
        )
        .chain(value =>
          fromEither(
            parseJSON(value, toError).chain(_ =>
              SAMLRequestCacheItem.decode(_).mapLeft(
                __ =>
                  new Error(
                    `SAML#ExtendedRedisCacheProvider: get() error ${readableReport(
                      __
                    )}`
                  )
              )
            )
          )
        );
    },
    remove(AuthnRequestID): TaskEither<Error, string> {
      return taskify(
        (key: string, callback: (err: Error | null, value?: unknown) => void) =>
          redisClient.del(key, callback)
      )(`${keyPrefix}${AuthnRequestID}`)
        .mapLeft(
          err =>
            new Error(`SAML#ExtendedRedisCacheProvider: remove() error ${err}`)
        )
        .map(() => AuthnRequestID);
    }
  };
};
