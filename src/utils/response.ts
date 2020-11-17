import { DOMParser } from "xmldom";

import { NextFunction, Request, Response } from "express";
import { fromNullable, none, Option, some, tryCatch } from "fp-ts/lib/Option";
import { ResponseErrorInternal } from "italia-ts-commons/lib/responses";
import { SAML_NAMESPACE } from "./saml";

/**
 * Extract AuthnContextClassRef from SAML response.
 *
 * ie. for <saml2:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml2:AuthnContextClassRef>
 * returns "https://www.spid.gov.it/SpidL2"
 */
export function getAuthnContextFromResponse(xml: string): Option<string> {
  return fromNullable(xml)
    .chain(xmlStr => tryCatch(() => new DOMParser().parseFromString(xmlStr)))
    .chain(xmlResponse =>
      xmlResponse
        ? some(
            xmlResponse.getElementsByTagNameNS(
              SAML_NAMESPACE.ASSERTION,
              "AuthnContextClassRef"
            )
          )
        : none
    )
    .chain(responseAuthLevelEl =>
      responseAuthLevelEl &&
      responseAuthLevelEl[0] &&
      responseAuthLevelEl[0].textContent
        ? some(responseAuthLevelEl[0].textContent.trim())
        : none
    );
}

export function middlewareCatchAsInternalError(
  f: (req: Request, res: Response, next: NextFunction) => unknown,
  message: string = "Exception while calling express middleware"
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      f(req, res, next);
    } catch (_) {
      // Send a ResponseErrorInternal only if a response was not already sent to the client
      if (!res.headersSent) {
        return ResponseErrorInternal(`${message} [${_}]`).apply(res);
      }
    }
  };
}
