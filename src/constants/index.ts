import { CountryName } from "../types/countries"

/**
 * List of countries that are sanctioned by the US government.
 */
const SANCTIONED_COUNTRIES: CountryName[] = [
  "North Korea",
  "Iran",
  "Iraq",
  "Libya",
  "Somalia",
  "Sudan",
  "Syrian Arab Republic",
  "Yemen",
]

/**
 * List of countries that are part of the European Union.
 */
const EU_COUNTRIES: CountryName[] = [
  "Austria",
  "Belgium",
  "Bulgaria",
  "Croatia",
  "Cyprus",
  "Czech Republic",
  "Denmark",
  "Estonia",
  "Finland",
  "France",
  "Germany",
  "Greece",
  "Hungary",
  "Ireland",
  "Italy",
  "Latvia",
  "Lithuania",
  "Luxembourg",
  "Malta",
  "Netherlands",
  "Poland",
  "Portugal",
  "Romania",
  "Slovakia",
  "Slovenia",
  "Spain",
  "Sweden",
]

/**
 * List of countries that are part of the European Economic Area.
 */
const EEA_COUNTRIES: CountryName[] = [...EU_COUNTRIES, "Iceland", "Liechtenstein", "Norway"]

/**
 * List of countries that are part of the Schengen Area.
 */
const SCHENGEN_COUNTRIES: CountryName[] = [
  ...EU_COUNTRIES.filter((country) => country !== "Cyprus" && country !== "Ireland"),
  "Switzerland",
  "Iceland",
  "Liechtenstein",
  "Norway",
]

/**
 * List of countries that are part of the Association of Southeast Asian Nations.
 */
const ASEAN_COUNTRIES: CountryName[] = [
  "Brunei Darussalam",
  "Cambodia",
  "Indonesia",
  "Lao People's Democratic Republic",
  "Malaysia",
  "Myanmar",
  "Philippines",
  "Singapore",
  "Thailand",
  "Vietnam",
]

/**
 * List of countries that are part of the Mercosur.
 */
const MERCOSUR_COUNTRIES: CountryName[] = [
  "Argentina",
  "Brazil",
  "Chile",
  "Colombia",
  "Paraguay",
  "Uruguay",
]

const SIGNED_ATTR_INPUT_SIZE = 200
const DG1_INPUT_SIZE = 95
const E_CONTENT_INPUT_SIZE = 700
const CERTIFICATE_REGISTRY_HEIGHT = 2
const CERTIFICATE_PAD_EMPTY_LEAVES = 10000
const CERTIFICATE_REGISTRY_ID = 1
const CERT_TYPE_CSC = 1
const CERT_TYPE_DSC = 2

// Doing it this way as this fixes a weird issue where the constant arrays are not being exported
// if you export them directly when they are declared
export {
  SANCTIONED_COUNTRIES,
  EU_COUNTRIES,
  EEA_COUNTRIES,
  SCHENGEN_COUNTRIES,
  ASEAN_COUNTRIES,
  MERCOSUR_COUNTRIES,
  SIGNED_ATTR_INPUT_SIZE,
  DG1_INPUT_SIZE,
  E_CONTENT_INPUT_SIZE,
  CERTIFICATE_REGISTRY_HEIGHT,
  CERTIFICATE_PAD_EMPTY_LEAVES,
  CERTIFICATE_REGISTRY_ID,
  CERT_TYPE_CSC,
  CERT_TYPE_DSC,
}
