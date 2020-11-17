export const SPID_IDP_IDENTIFIERS = {
  "https://id.lepida.it/idp/shibboleth": "lepidaid",
  "https://identity.infocert.it": "infocertid",
  "https://identity.sieltecloud.it": "sielteid",
  "https://idp.namirialtsp.com/idp": "namirialid",
  "https://login.id.tim.it/affwebservices/public/saml2sso": "timid",
  "https://loginspid.aruba.it": "arubaid",
  "https://posteid.poste.it": "posteid",
  "https://spid.intesa.it": "intesaid",
  "https://spid.register.it": "spiditalia"
};

export const CIE_IDP_IDENTIFIERS = {
  "https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO":
    "xx_servizicie",
  "https://idserver.servizicie.interno.gov.it:8443/idp/profile/SAML2/POST/SSO":
    "xx_servizicie_test"
};

/*
 * @see https://www.agid.gov.it/sites/default/files/repository_files/regole_tecniche/tabella_attributi_idp.pdf
 */
export const SPID_USER_ATTRIBUTES = {
  address: "Indirizzo",
  companyName: "Nome azienda",
  dateOfBirth: "Data di nascita",
  digitalAddress: "Indirizzo elettronico",
  email: "Email",
  familyName: "Cognome",
  fiscalNumber: "Codice fiscale",
  gender: "Sesso",
  idCard: "Numero carta di identità",
  ivaCode: "Codice IVA",
  mobilePhone: "Numero di telefono",
  name: "Nome",
  placeOfBirth: "Luogo di nascita",
  registeredOffice: "Ufficio",
  spidCode: "Codice SPID"
};

export const SPID_LEVELS = {
  SpidL1: "https://www.spid.gov.it/SpidL1",
  SpidL2: "https://www.spid.gov.it/SpidL2",
  SpidL3: "https://www.spid.gov.it/SpidL3"
};

export const SPID_URLS = {
  "https://www.spid.gov.it/SpidL1": "SpidL1",
  "https://www.spid.gov.it/SpidL2": "SpidL2",
  "https://www.spid.gov.it/SpidL3": "SpidL3"
};
