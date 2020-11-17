#!/usr/bin/env node

import { array } from "fp-ts/lib/Array";
import { fromNullable } from "fp-ts/lib/Option";
import { task } from "fp-ts/lib/Task";
import * as yargs from "yargs";
import { logger } from "../utils/logger";
import { fetchMetadataXML } from "../utils/metadata";

//
// parse command line
//
const argv = yargs
  .option("idp-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing IDP Metadata URL",
    normalize: true,
    string: true
  })
  .option("testenv-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing TestEnv2 Metadata URL",
    normalize: true,
    string: true
  })
  .option("cie-metadata-url-env", {
    demandOption: false,
    description: "ENV var name containing CIE Metadata URL",
    normalize: true,
    string: true
  })
  .help().argv;

interface IIDPSMetadataXML {
  idps?: string;
  xx_testenv2?: string;
  xx_servizicie?: string;
}

function printIdpsMetadata(
  idpsMetadataENV: string | undefined,
  testEnv2MetadataENV: string | undefined,
  cieMetadataENV: string | undefined
): Promise<IIDPSMetadataXML> {
  // tslint:disable: no-object-mutation no-any no-empty
  logger.info = (): any => {};
  const maybeIdpsMetadataURL = fromNullable(idpsMetadataENV)
    .mapNullable(_ => process.env[_])
    .map((_: string) =>
      fetchMetadataXML(_)
        .map<{ idps?: string }>(_1 => ({
          idps: _1
        }))
        .getOrElse({})
    )
    .getOrElse(task.of({}));
  const maybeTestEnvMetadataURL = fromNullable(testEnv2MetadataENV)
    .mapNullable(_ => process.env[_])
    .map((_: string) =>
      fetchMetadataXML(`${_}/metadata`)
        .map<{ xx_testenv2?: string }>(_1 => ({
          xx_testenv2: _1
        }))
        .getOrElse({})
    )
    .getOrElse(task.of({}));
  const maybeCIEMetadataURL = fromNullable(cieMetadataENV)
    .mapNullable(_ => process.env[_])
    .map((_: string) =>
      fetchMetadataXML(_)
        .map<{ xx_servizicie?: string }>(_1 => ({
          xx_servizicie: _1
        }))
        .getOrElse({})
    )
    .getOrElse(task.of({}));
  return array
    .sequence(task)<IIDPSMetadataXML>([
      maybeIdpsMetadataURL,
      maybeTestEnvMetadataURL,
      maybeCIEMetadataURL
    ])
    .map(_ => _.reduce((prev, current) => ({ ...prev, ...current }), {}))
    .run();
}

printIdpsMetadata(
  argv["idp-metadata-url-env"],
  argv["testenv-metadata-url-env"],
  argv["cie-metadata-url-env"]
)
  // tslint:disable-next-line: no-console
  .then(metadata => console.log(JSON.stringify(metadata, null, 2)))
  .catch(() => logger.error("Error fetching IDP metadata"));
