/**
 * Methods to fetch and parse Identity service providers metadata.
 */
import {
  Either,
  fromPredicate as eitherFromPredicate,
  right,
  toError
} from "fp-ts/lib/Either";
import { StrMap } from "fp-ts/lib/StrMap";
import {
  fromEither,
  fromPredicate,
  TaskEither,
  tryCatch
} from "fp-ts/lib/TaskEither";
import { errorsToReadableMessages } from "italia-ts-commons/lib/reporters";
import nodeFetch from "node-fetch";
import { DOMParser } from "xmldom";
import { CIE_IDP_IDENTIFIERS, SPID_IDP_IDENTIFIERS } from "../config";
import { IDPEntityDescriptor } from "../types/IDPEntityDescriptor";
import { logger } from "./logger";

const EntityDescriptorTAG = "EntityDescriptor";
const X509CertificateTAG = "X509Certificate";
const SingleSignOnServiceTAG = "SingleSignOnService";
const SingleLogoutServiceTAG = "SingleLogoutService";

const METADATA_NAMESPACES = {
  METADATA: "urn:oasis:names:tc:SAML:2.0:metadata",
  XMLDSIG: "http://www.w3.org/2000/09/xmldsig#"
};

/**
 * Parse a string that represents an XML file containing
 * the ipd Metadata and converts it into an array of IDPEntityDescriptor
 *
 * Required namespace definitions into the XML are
 *  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" and xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 *
 * An example file is provided in /test_idps/spid-entities-idps.xml of this project.
 */
export function parseIdpMetadata(
  ipdMetadataPage: string
): Either<Error, ReadonlyArray<IDPEntityDescriptor>> {
  return right<Error, Document>(
    new DOMParser().parseFromString(ipdMetadataPage)
  )
    .chain(
      eitherFromPredicate(
        domParser =>
          domParser && !domParser.getElementsByTagName("parsererror").item(0),
        () => new Error("XML parser error")
      )
    )
    .chain(domParser => {
      const entityDescriptors = domParser.getElementsByTagNameNS(
        METADATA_NAMESPACES.METADATA,
        EntityDescriptorTAG
      );
      return right(
        Array.from(entityDescriptors).reduce(
          (idps: ReadonlyArray<IDPEntityDescriptor>, element: Element) => {
            const certs = Array.from(
              element.getElementsByTagNameNS(
                METADATA_NAMESPACES.XMLDSIG,
                X509CertificateTAG
              )
            ).map(_ =>
              _.textContent ? _.textContent.replace(/[\n\s]/g, "") : ""
            );
            return IDPEntityDescriptor.decode({
              cert: certs,
              entityID: element.getAttribute("entityID"),
              entryPoint: Array.from(
                element.getElementsByTagNameNS(
                  METADATA_NAMESPACES.METADATA,
                  SingleSignOnServiceTAG
                )
              )
                .filter(
                  _ =>
                    _.getAttribute("Binding") ===
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                )[0]
                ?.getAttribute("Location"),
              logoutUrl:
                Array.from(
                  element.getElementsByTagNameNS(
                    METADATA_NAMESPACES.METADATA,
                    SingleLogoutServiceTAG
                  )
                )
                  .filter(
                    _ =>
                      _.getAttribute("Binding") ===
                      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                  )[0]
                  // If SingleLogoutService is missing will be return an empty string
                  // Needed for CIE Metadata
                  ?.getAttribute("Location") || ""
            }).fold(
              errs => {
                logger.warn(
                  "Invalid md:EntityDescriptor. %s",
                  errorsToReadableMessages(errs).join(" / ")
                );
                return idps;
              },
              elementInfo => [...idps, elementInfo]
            );
          },
          []
        )
      );
    });
}

/**
 * Map provided idpMetadata into an object with idp key whitelisted in ipdIds.
 * Mapping is based on entityID property
 */
export const mapIpdMetadata = (
  idpMetadata: ReadonlyArray<IDPEntityDescriptor>,
  idpIds: Record<string, string>
): Record<string, IDPEntityDescriptor> =>
  idpMetadata.reduce<Record<string, IDPEntityDescriptor>>((prev, idp) => {
    const idpKey = idpIds[idp.entityID];
    if (idpKey) {
      return { ...prev, [idpKey]: idp };
    }
    logger.warn(
      `Unsupported SPID idp from metadata repository [${idp.entityID}]`
    );
    return prev;
  }, {});

/**
 * Fetch an XML from a remote URL
 */
export function fetchMetadataXML(
  idpMetadataUrl: string
): TaskEither<Error, string> {
  return tryCatch(() => {
    logger.info("Fetching SPID metadata from [%s]...", idpMetadataUrl);
    return nodeFetch(idpMetadataUrl);
  }, toError)
    .chain(
      fromPredicate(
        p => p.status >= 200 && p.status < 300,
        () => {
          logger.warn("Error fetching remote metadata for %s", idpMetadataUrl);
          return new Error("Error fetching remote metadata");
        }
      )
    )
    .chain(p => tryCatch(() => p.text(), toError));
}

/**
 * Load idp Metadata from a remote url, parse infos and return a mapped and whitelisted idp options
 * for spidStrategy object.
 */
export function fetchIdpsMetadata(
  idpMetadataUrl: string,
  idpIds: Record<string, string>
): TaskEither<Error, Record<string, IDPEntityDescriptor>> {
  return fetchMetadataXML(idpMetadataUrl)
    .chain(idpMetadataXML => {
      logger.info("Parsing SPID metadata for %s", idpMetadataUrl);
      return fromEither(parseIdpMetadata(idpMetadataXML));
    })
    .chain(
      fromPredicate(
        idpMetadata => idpMetadata.length > 0,
        () => {
          logger.error("No SPID metadata found for %s", idpMetadataUrl);
          return new Error("No SPID metadata found");
        }
      )
    )
    .map(idpMetadata => {
      if (!idpMetadata.length) {
        logger.warn("Missing SPID metadata on %s", idpMetadataUrl);
      }
      logger.info("Configuring IdPs for %s", idpMetadataUrl);
      return mapIpdMetadata(idpMetadata, idpIds);
    });
}

/**
 * This method expects in input a Record where key are idp identifier
 * and values are an XML string (idp metadata).
 * Provided metadata are parsed and converted into IDP Entity Descriptor objects.
 */
export function parseStartupIdpsMetadata(
  idpsMetadata: Record<string, string>
): Record<string, IDPEntityDescriptor> {
  return mapIpdMetadata(
    new StrMap(idpsMetadata).reduce(
      [] as ReadonlyArray<IDPEntityDescriptor>,
      (prev, metadataXML) => [
        ...prev,
        ...parseIdpMetadata(metadataXML).getOrElse([])
      ]
    ),
    { ...SPID_IDP_IDENTIFIERS, ...CIE_IDP_IDENTIFIERS } // TODO: Add TestEnv IDP identifier
  );
}
