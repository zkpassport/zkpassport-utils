import cscMasterlistFile from "./assets/certificates/csc-masterlist.json"
import {
  CERTIFICATE_REGISTRY_HEIGHT,
  CERTIFICATE_REGISTRY_ID,
  DG1_INPUT_SIZE,
  SIGNED_ATTR_INPUT_SIZE,
} from "./constants"
import { computeMerkleProof } from "./merkle-tree"
import {
  Certificate,
  CSCMasterlist,
  DiscloseFlags,
  ECDSACSCPublicKey,
  ECDSADSCDataInputs,
  IDCredential,
  IDDataInputs,
  PassportViewModel,
  Query,
  RSACSCPublicKey,
  RSADSCDataInputs,
} from "./types"
import { AsnParser } from "@peculiar/asn1-schema"
import { AuthorityKeyIdentifier, PrivateKeyUsagePeriod } from "@peculiar/asn1-x509"
import { format } from "date-fns"
import { redcLimbsFromBytes } from "./barrett-reduction"
import { Binary } from "./binary"
import {
  calculatePrivateNullifier,
  getCertificateLeafHash,
  getCountryWeightedSum,
  hashSaltCountrySignedAttrDg1PrivateNullifier,
  hashSaltCountryTbs,
  hashSaltDg1PrivateNullifier,
} from "./circuits"
import {
  extractTBS,
  getDSCSignatureAlgorithmType,
  getECDSAInfo,
  getRSAInfo,
  getSodSignatureAlgorithmType,
} from "./passport-reader/passport-reader"
import {
  bigintToBytes,
  bigintToNumber,
  getBitSize,
  getOffsetInArray,
  padArrayWithZeros,
} from "./utils"
import { parseDate } from "./circuits/disclose"
import { alpha2ToAlpha3, Alpha3Code } from "i18n-iso-countries"

export function isSignatureAlgorithmSupported(
  passport: PassportViewModel,
  signatureAlgorithm: "RSA" | "ECDSA" | "",
): boolean {
  const tbsCertificate = extractTBS(passport)
  if (!tbsCertificate) {
    return false
  }
  if (signatureAlgorithm === "ECDSA") {
    const ecdsaInfo = getECDSAInfo(tbsCertificate)
    return ecdsaInfo.curve === "P-256"
  } else if (signatureAlgorithm === "RSA") {
    const rsaInfo = getRSAInfo(tbsCertificate)
    const modulusBits = getBitSize(rsaInfo.modulus)
    return (
      (modulusBits === 1024 ||
        modulusBits === 2048 ||
        modulusBits === 3072 ||
        modulusBits === 4096) &&
      (rsaInfo.exponent === 3n || rsaInfo.exponent === 65537n)
    )
  }
  return false
}

export function isDocumentSODSupported(passport: PassportViewModel): boolean {
  const signatureAlgorithm = getSodSignatureAlgorithmType(passport)
  return isSignatureAlgorithmSupported(passport, signatureAlgorithm)
}

export function isDocumentDSCSupported(passport: PassportViewModel): boolean {
  const signatureAlgorithm = getDSCSignatureAlgorithmType(passport)
  return isSignatureAlgorithmSupported(passport, signatureAlgorithm)
}

export function getCSCMasterlist(): CSCMasterlist {
  return cscMasterlistFile as CSCMasterlist
}

export function getTBSMaxLen(passport: PassportViewModel): number {
  const tbs_len = passport.sod.certificate.tbs.bytes.length
  if (tbs_len <= 700) {
    return 700
  } else if (tbs_len <= 1000) {
    return 1000
  } else if (tbs_len <= 1200) {
    return 1200
  } else {
    return 1500
  }
}

export function getCSCForPassport(
  passport: PassportViewModel,
  masterlist?: CSCMasterlist,
): Certificate | null {
  const cscMasterlist = masterlist ?? getCSCMasterlist()
  const extensions = passport.sod.certificate.tbs.extensions

  let notBefore: number | undefined
  let notAfter: number | undefined
  const pkupBuffer = extensions.get("privateKeyUsagePeriod")?.value.toBuffer()
  if (pkupBuffer) {
    const pkup = AsnParser.parse(pkupBuffer, PrivateKeyUsagePeriod)
    notBefore = pkup.notBefore?.getTime() ?? 0 / 1000
    notAfter = pkup.notAfter?.getTime() ?? 0 / 1000
  }

  let authorityKeyIdentifier: string | undefined
  const akiBuffer = extensions.get("authorityKeyIdentifier")?.value.toBuffer()
  if (akiBuffer) {
    const parsed = AsnParser.parse(akiBuffer, AuthorityKeyIdentifier)
    if (parsed?.keyIdentifier?.buffer) {
      authorityKeyIdentifier = Binary.from(parsed.keyIdentifier.buffer).toHex().replace("0x", "")
    }
  }
  const country = getDSCCountry(passport)
  const formattedCountry = country === "D<<" ? "DEU" : country

  const checkAgainstAuthorityKeyIdentifier = (cert: Certificate) => {
    return (
      authorityKeyIdentifier &&
      cert.subject_key_identifier?.replace("0x", "") === authorityKeyIdentifier
    )
  }

  const checkAgainstPrivateKeyUsagePeriod = (cert: Certificate) => {
    return (
      cert.private_key_usage_period &&
      cert.private_key_usage_period?.not_before &&
      cert.private_key_usage_period?.not_after &&
      notBefore &&
      notAfter &&
      notBefore >= (cert.private_key_usage_period?.not_before || 0) &&
      notAfter <= (cert.private_key_usage_period?.not_after || 0)
    )
  }

  const certificate = cscMasterlist.certificates.find((cert) => {
    return (
      cert.country.toLowerCase() === formattedCountry.toLowerCase() &&
      (checkAgainstAuthorityKeyIdentifier(cert) || checkAgainstPrivateKeyUsagePeriod(cert))
    )
  })
  if (!certificate) {
    console.warn(`Could not find CSC for DSC`)
  }
  return certificate ?? null
}

function getDSCDataInputs(
  passport: PassportViewModel,
  maxTbsLength: number,
): ECDSADSCDataInputs | RSADSCDataInputs | null {
  const signatureAlgorithm = getSodSignatureAlgorithmType(passport)
  const tbsCertificate = extractTBS(passport)
  if (!tbsCertificate) {
    return null
  }
  if (signatureAlgorithm === "ECDSA") {
    const ecdsaInfo = getECDSAInfo(tbsCertificate)
    return {
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], maxTbsLength),
      pubkey_offset_in_tbs: getOffsetInArray(
        passport?.tbsCertificate ?? [],
        Array.from(ecdsaInfo.publicKey.slice(0, 32)),
      ),
      dsc_pubkey_x: Array.from(ecdsaInfo.publicKey.slice(0, 32)),
      dsc_pubkey_y: Array.from(ecdsaInfo.publicKey.slice(32)),
    }
  } else {
    const { modulus, exponent } = getRSAInfo(tbsCertificate)
    const modulusBytes = bigintToBytes(modulus)
    return {
      dsc_pubkey: modulusBytes,
      exponent: bigintToNumber(exponent),
      dsc_pubkey_redc_param: redcLimbsFromBytes(modulusBytes),
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], maxTbsLength),
      pubkey_offset_in_tbs: getOffsetInArray(passport?.tbsCertificate ?? [], modulusBytes),
    }
  }
}

function getIDDataInputs(passport: PassportViewModel): IDDataInputs {
  const dg1 = passport?.dataGroups.find((dg) => dg.groupNumber === 1)
  const dg1Offset = getOffsetInArray(passport?.eContent ?? [], dg1?.hash ?? [])
  const id_data = {
    // Padded with 0s to make it 700 bytes
    e_content: padArrayWithZeros(passport?.eContent ?? [], 700),
    e_content_size: passport?.eContent?.length ?? 0,
    dg1_offset_in_e_content: dg1Offset,
    // Padded to 200 bytes with 0s
    signed_attributes: padArrayWithZeros(passport?.signedAttributes ?? [], 200),
    signed_attributes_size: passport?.signedAttributes?.length ?? 0,
    // Padded to 95 bytes with 0s
    dg1: padArrayWithZeros(dg1?.value ?? [], 95),
  }
  return id_data
}

export async function getDSCCircuitInputs(
  passport: PassportViewModel,
  salt: bigint,
  merkleTreeLeaves?: Binary[],
  masterlist?: CSCMasterlist,
): Promise<any> {
  // Get the CSC for this passport's DSC
  const csc = getCSCForPassport(passport, masterlist)
  if (!csc) return null

  // Generate the certificate registry merkle proof
  const cscMasterlist = masterlist ?? getCSCMasterlist()
  const leaves =
    merkleTreeLeaves ??
    cscMasterlist.certificates.map((cert) => Binary.fromHex(getCertificateLeafHash(cert)))
  const index = cscMasterlist.certificates.findIndex((cert) => cert === csc)
  const merkleProof = await computeMerkleProof(leaves, index, CERTIFICATE_REGISTRY_HEIGHT)
  const inputs = {
    certificate_registry_root: merkleProof.root,
    certificate_registry_index: merkleProof.index,
    certificate_registry_hash_path: merkleProof.path,
    certificate_registry_id: CERTIFICATE_REGISTRY_ID,
    certificate_type: 1,
    country: csc.country,
    salt: salt.toString(),
  }

  const signatureAlgorithm = getDSCSignatureAlgorithmType(passport)
  const maxTbsLength = getTBSMaxLen(passport)
  if (signatureAlgorithm === "ECDSA") {
    const cscPublicKey = csc?.public_key as ECDSACSCPublicKey
    const publicKeyXBytes = Buffer.from(cscPublicKey.public_key_x ?? "", "hex")
    const publicKeyYBytes = Buffer.from(cscPublicKey.public_key_y ?? "", "hex")
    return {
      ...inputs,
      csc_pubkey_x: Array.from(publicKeyXBytes),
      csc_pubkey_y: Array.from(publicKeyYBytes),
      dsc_signature: passport?.dscSignature ?? [],
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], maxTbsLength),
      tbs_certificate_len: passport?.tbsCertificate?.length,
    }
  } else if (signatureAlgorithm === "RSA") {
    const cscPublicKey = csc?.public_key as RSACSCPublicKey
    const modulusBytes = bigintToBytes(BigInt(cscPublicKey.modulus))
    return {
      ...inputs,
      tbs_certificate: padArrayWithZeros(passport?.tbsCertificate ?? [], maxTbsLength),
      tbs_certificate_len: passport?.tbsCertificate?.length,
      dsc_signature: passport?.dscSignature ?? [],
      csc_pubkey: modulusBytes,
      csc_pubkey_redc_param: redcLimbsFromBytes(modulusBytes),
      exponent: cscPublicKey.exponent,
    }
  }
}

export function getIDDataCircuitInputs(passport: PassportViewModel, salt: bigint): any {
  const idData = getIDDataInputs(passport)
  const maxTbsLength = getTBSMaxLen(passport)
  const dscData = getDSCDataInputs(passport, maxTbsLength)
  if (!dscData || !idData) return null

  const commIn = hashSaltCountryTbs(
    salt,
    getDSCCountry(passport),
    Binary.from(passport.tbsCertificate),
    maxTbsLength,
  )

  const inputs = {
    dg1: idData.dg1,
    signed_attributes: idData.signed_attributes,
    signed_attributes_size: idData.signed_attributes_size,
    comm_in: commIn.toHex(),
    salt: salt.toString(),
  }

  const signatureAlgorithm = getSodSignatureAlgorithmType(passport)
  if (signatureAlgorithm === "ECDSA") {
    return {
      ...inputs,
      tbs_certificate: dscData.tbs_certificate,
      pubkey_offset_in_tbs: dscData.pubkey_offset_in_tbs,
      dsc_pubkey_x: (dscData as ECDSADSCDataInputs).dsc_pubkey_x,
      dsc_pubkey_y: (dscData as ECDSADSCDataInputs).dsc_pubkey_y,
      sod_signature: passport?.sodSignature ?? [],
      signed_attributes: idData.signed_attributes,
      signed_attributes_size: idData.signed_attributes_size,
    }
  } else if (signatureAlgorithm === "RSA") {
    return {
      ...inputs,
      dsc_pubkey: (dscData as RSADSCDataInputs).dsc_pubkey,
      exponent: (dscData as RSADSCDataInputs).exponent,
      sod_signature: passport?.sodSignature ?? [],
      dsc_pubkey_redc_param: (dscData as RSADSCDataInputs).dsc_pubkey_redc_param,
      tbs_certificate: (dscData as RSADSCDataInputs).tbs_certificate,
      pubkey_offset_in_tbs: (dscData as RSADSCDataInputs).pubkey_offset_in_tbs,
      signed_attributes: idData.signed_attributes,
      signed_attributes_size: idData.signed_attributes_size,
    }
  }
}

export function getDSCCountry(passport: PassportViewModel): string {
  const country = passport.sod.certificate.tbs.issuer?.match(/countryName=([A-Z]+)/)?.[1]
  const formattedCountryCode = country?.length === 2 ? alpha2ToAlpha3(country) : country
  return formattedCountryCode ?? passport.nationality
}

export function getIntegrityCheckCircuitInputs(passport: PassportViewModel, salt: bigint): any {
  const maxTbsLength = getTBSMaxLen(passport)
  const dscData = getDSCDataInputs(passport, maxTbsLength)
  if (!dscData) return null
  const idData = getIDDataInputs(passport)
  if (!idData) return null

  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const comm_in = hashSaltCountrySignedAttrDg1PrivateNullifier(
    salt,
    getDSCCountry(passport),
    Binary.from(passport.signedAttributes).padEnd(SIGNED_ATTR_INPUT_SIZE),
    BigInt(passport.signedAttributes.length),
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  return {
    current_date: format(new Date(), "yyyyMMdd"),
    dg1: idData.dg1,
    signed_attributes: idData.signed_attributes,
    signed_attributes_size: idData.signed_attributes_size,
    e_content: idData.e_content,
    e_content_size: idData.e_content_size,
    dg1_offset_in_e_content: idData.dg1_offset_in_e_content,
    comm_in: comm_in.toHex(),
    private_nullifier: privateNullifier.toHex(),
    salt: salt.toString(),
  }
}

export function getFirstNameRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  const lastNameStartIndex = isIDCard ? 60 : 5
  const firstNameStartIndex = getOffsetInArray(mrz.split(""), ["<", "<"], lastNameStartIndex) + 2
  const firstNameEndIndex = getOffsetInArray(mrz.split(""), ["<", "<"], firstNameStartIndex)
  return [firstNameStartIndex, firstNameEndIndex]
}

export function getLastNameRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  const lastNameStartIndex = isIDCard ? 60 : 5
  const lastNameEndIndex = getOffsetInArray(mrz.split(""), ["<", "<"], lastNameStartIndex)
  return [lastNameStartIndex, lastNameEndIndex]
}

export function getFullNameRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 60 : 5, isIDCard ? 90 : 44]
}

function getBirthdateRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 30 : 57, isIDCard ? 36 : 63]
}

function getDocumentNumberRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 5 : 44, isIDCard ? 14 : 53]
}

function getNationalityRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 45 : 54, isIDCard ? 48 : 57]
}

function getExpiryDateRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 38 : 65, isIDCard ? 44 : 71]
}

function getGenderRange(passport: PassportViewModel): [number, number] {
  const mrz = passport?.mrz
  const isIDCard = mrz.length == 90
  return [isIDCard ? 37 : 64, isIDCard ? 38 : 65]
}

export function getDiscloseCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  const discloseMask = Array(90).fill(0)
  let fieldsToDisclose: { [key in IDCredential]: boolean } = {} as any
  for (const field in query) {
    if (query[field as IDCredential]?.disclose) {
      fieldsToDisclose[field as IDCredential] = true
    }
  }
  for (const field in fieldsToDisclose) {
    if (fieldsToDisclose[field as IDCredential]) {
      switch (field as IDCredential) {
        case "firstname":
          const firstNameRange = getFirstNameRange(passport)
          discloseMask.fill(1, firstNameRange[0], firstNameRange[1])
          break
        case "lastname":
          const lastNameRange = getLastNameRange(passport)
          discloseMask.fill(1, lastNameRange[0], lastNameRange[1])
          break
        case "fullname":
          const fullNameRange = getFullNameRange(passport)
          discloseMask.fill(1, fullNameRange[0], fullNameRange[1])
          break
        case "birthdate":
          const birthdateRange = getBirthdateRange(passport)
          discloseMask.fill(1, birthdateRange[0], birthdateRange[1])
          break
        case "document_number":
          const documentNumberRange = getDocumentNumberRange(passport)
          discloseMask.fill(1, documentNumberRange[0], documentNumberRange[1])
          break
        case "nationality":
          const nationalityRange = getNationalityRange(passport)
          discloseMask.fill(1, nationalityRange[0], nationalityRange[1])
          break
        case "document_type":
          discloseMask.fill(1, 0, 2)
          break
        case "expiry_date":
          const expiryDateRange = getExpiryDateRange(passport)
          discloseMask.fill(1, expiryDateRange[0], expiryDateRange[1])
          break
        case "gender":
          const genderRange = getGenderRange(passport)
          discloseMask.fill(1, genderRange[0], genderRange[1])
          break
        case "issuing_country":
          discloseMask.fill(1, 2, 5)
          break
      }
    }
  }
  return {
    dg1: idData.dg1,
    disclose_mask: discloseMask,
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
  }
}

export function getDiscloseFlagsCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  const discloseFlags: DiscloseFlags = {
    issuing_country: query.issuing_country?.disclose ?? false,
    nationality: query.nationality?.disclose ?? false,
    document_type: query.document_type?.disclose ?? false,
    document_number: query.document_number?.disclose ?? false,
    date_of_expiry: query.expiry_date?.disclose ?? false,
    date_of_birth: query.birthdate?.disclose ?? false,
    gender: query.gender?.disclose ?? false,
    name: query.fullname?.disclose ?? false,
  }

  return {
    dg1: idData.dg1,
    disclose_flags: discloseFlags,
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
  }
}

export function calculateAge(passport: PassportViewModel): number {
  const birthdate = passport.dateOfBirth
  if (!birthdate) return 0
  const birthdateDate = parseDate(new TextEncoder().encode(birthdate))
  const currentDate = new Date()

  let age = currentDate.getFullYear() - birthdateDate.getFullYear()
  const monthDiff = currentDate.getMonth() - birthdateDate.getMonth()
  if (monthDiff < 0 || (monthDiff === 0 && currentDate.getDate() < birthdateDate.getDate())) {
    age--
  }
  return age
}

export function getAgeCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  let age = calculateAge(passport)

  let minAge = 0
  let maxAge = 0
  if (query.age) {
    if (query.age.gt) {
      minAge = query.age.gt as number
    } else if (query.age.gte) {
      minAge = query.age.gte as number
    } else if (query.age.range) {
      minAge = query.age.range[0] as number
      maxAge = query.age.range[1] as number
    } else if (query.age.eq) {
      minAge = query.age.eq as number
      maxAge = query.age.eq as number
    } else if (query.age.disclose) {
      minAge = age
      maxAge = age
    }

    if (query.age.lt) {
      maxAge = query.age.lt as number
    } else if (query.age.lte) {
      maxAge = query.age.lte as number
    }
  }

  return {
    dg1: idData.dg1,
    current_date: format(new Date(), "yyyyMMdd"),
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
    min_age_required: minAge,
    max_age_required: maxAge,
  }
}

function padCountryList(countryList: string[]): string[] {
  const paddedCountryList = Array(200).fill(new TextDecoder().decode(new Uint8Array([0, 0, 0])))
  for (let i = 0; i < countryList.length; i++) {
    paddedCountryList[i] = countryList[i]
  }
  return paddedCountryList
}

export function getCountryInclusionCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  return {
    dg1: idData.dg1,
    country_list: padCountryList(query.nationality?.in ?? []),
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
  }
}

export function getCountryExclusionCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  const countryList: number[] = []
  for (let i = 0; i < (query.nationality?.out ?? []).length; i++) {
    const country: string = (query.nationality?.out ?? [])[i]
    countryList.push(...getCountryWeightedSum(country as Alpha3Code))
  }

  return {
    dg1: idData.dg1,
    // Sort the country list in ascending order
    country_list: padArrayWithZeros(
      countryList.sort((a, b) => a - b),
      200,
    ),
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
  }
}

export function getBirthdateCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  let minDate: Date | undefined
  let maxDate: Date | undefined
  if (query.birthdate) {
    if (query.birthdate.gt) {
      minDate = query.birthdate.gt as Date
    } else if (query.birthdate.gte) {
      minDate = query.birthdate.gte as Date
    } else if (query.birthdate.range) {
      minDate = query.birthdate.range[0] as Date
      maxDate = query.birthdate.range[1] as Date
    } else if (query.birthdate.eq) {
      minDate = query.birthdate.eq as Date
      maxDate = query.birthdate.eq as Date
    } else if (query.birthdate.disclose) {
      minDate = parseDate(new TextEncoder().encode(passport.dateOfBirth))
      maxDate = parseDate(new TextEncoder().encode(passport.dateOfBirth))
    }

    if (query.birthdate.lt) {
      maxDate = query.birthdate.lt as Date
    } else if (query.birthdate.lte) {
      maxDate = query.birthdate.lte as Date
    }
  }

  return {
    dg1: idData.dg1,
    current_date: format(new Date(), "yyyyMMdd"),
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
    // "11111111" means the date is ignored
    min_date: minDate ? format(minDate, "yyyyMMdd") : "1".repeat(8),
    max_date: maxDate ? format(maxDate, "yyyyMMdd") : "1".repeat(8),
  }
}

export function getExpiryDateCircuitInputs(
  passport: PassportViewModel,
  query: Query,
  salt: bigint,
  service_scope: bigint = 0n,
  service_subscope: bigint = 0n,
): any {
  const idData = getIDDataInputs(passport)
  if (!idData) return null
  const privateNullifier = calculatePrivateNullifier(
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    Binary.from(passport.sodSignature),
  )
  const commIn = hashSaltDg1PrivateNullifier(
    salt,
    Binary.from(idData.dg1).padEnd(DG1_INPUT_SIZE),
    privateNullifier.toBigInt(),
  )

  let minDate: Date | undefined
  let maxDate: Date | undefined
  if (query.expiry_date) {
    if (query.expiry_date.gt) {
      minDate = query.expiry_date.gt as Date
    } else if (query.expiry_date.gte) {
      minDate = query.expiry_date.gte as Date
    } else if (query.expiry_date.range) {
      minDate = query.expiry_date.range[0] as Date
      maxDate = query.expiry_date.range[1] as Date
    } else if (query.expiry_date.eq) {
      minDate = query.expiry_date.eq as Date
      maxDate = query.expiry_date.eq as Date
    } else if (query.expiry_date.disclose) {
      minDate = parseDate(new TextEncoder().encode(passport.passportExpiry))
      maxDate = parseDate(new TextEncoder().encode(passport.passportExpiry))
    }

    if (query.expiry_date.lt) {
      maxDate = query.expiry_date.lt as Date
    } else if (query.expiry_date.lte) {
      maxDate = query.expiry_date.lte as Date
    }
  }

  return {
    dg1: idData.dg1,
    current_date: format(new Date(), "yyyyMMdd"),
    comm_in: commIn.toHex(),
    private_nullifier: privateNullifier.toHex(),
    service_scope: service_scope.toString(),
    service_subscope: service_subscope.toString(),
    salt: salt.toString(),
    // "11111111" means the date is ignored
    min_date: minDate ? format(minDate, "yyyyMMdd") : "1".repeat(8),
    max_date: maxDate ? format(maxDate, "yyyyMMdd") : "1".repeat(8),
  }
}
