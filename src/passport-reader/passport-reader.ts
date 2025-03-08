import { Binary } from "../binary"
import { PassportViewModel } from "../types"
import { p256 } from "@noble/curves/p256"
import { p384 } from "@noble/curves/p384"
import { p521 } from "@noble/curves/p521"
import { ECParameters } from "@peculiar/asn1-ecc"
import { RSAPublicKey, RsaSaPssParams } from "@peculiar/asn1-rsa"
import { AsnParser } from "@peculiar/asn1-schema"
import { AlgorithmIdentifier, SubjectPublicKeyInfo, TBSCertificate } from "@peculiar/asn1-x509"
import { BRAINPOOL_CURVES, CURVE_OIDS, HASH_OIDS, RSA_OIDS } from "./constants"
import { DigestAlgorithm, SOD } from "./sod"
import { ASN } from "./asn"
import { decodeOID } from "./oids"

export class PassportReader {
  public dg1?: Binary
  public sod?: SOD

  getPassportViewModel(): PassportViewModel {
    if (this.dg1 === undefined || this.sod === undefined) {
      throw new Error("PassportReader not initialized")
    }
    const isIDCard = this.dg1.length === 95
    const mrz = this.dg1.slice(5).toString("ascii")
    // TODO: Implement the remaining properties
    return {
      appVersion: "",
      mrz: mrz,
      name: mrz.slice(isIDCard ? 60 : 5, isIDCard ? 90 : 44),
      dateOfBirth: mrz.slice(isIDCard ? 30 : 57, isIDCard ? 36 : 63),
      nationality: mrz.slice(isIDCard ? 45 : 54, isIDCard ? 48 : 57),
      gender: mrz.slice(isIDCard ? 37 : 64, isIDCard ? 38 : 65),
      passportNumber: mrz.slice(isIDCard ? 5 : 44, isIDCard ? 14 : 53),
      passportExpiry: mrz.slice(isIDCard ? 38 : 65, isIDCard ? 44 : 71),
      firstName: "",
      lastName: "",
      fullName: mrz.slice(isIDCard ? 60 : 5, isIDCard ? 90 : 44),
      photo: "",
      originalPhoto: "",

      chipAuthSupported: false,
      chipAuthSuccess: false,
      chipAuthFailed: false,

      LDSVersion: "",

      // TODO: Add support for other data groups
      dataGroups: Object.entries(this.sod.encapContentInfo.eContent.dataGroupHashValues.values).map(
        ([key, value]) => ({
          groupNumber: Number(key),
          name: "DG" + key,
          hash: value.toNumberArray(),
          value: key === "1" ? this.dg1?.toNumberArray() ?? [] : [],
        }),
      ),
      dataGroupsHashAlgorithm: this.sod.encapContentInfo.eContent.hashAlgorithm,

      sod: this.sod,

      sodVersion: this.sod.version.toString(),

      signedAttributes: this.sod.signerInfo.signedAttrs.bytes.toNumberArray(),
      signedAttributesHashAlgorithm: this.sod.signerInfo.digestAlgorithm,
      eContent: this.sod.encapContentInfo.eContent.bytes.toNumberArray(),
      eContentHash: this.sod.signerInfo.signedAttrs.messageDigest.toHex(),
      eContentHashAlgorithm: this.sod.signerInfo.digestAlgorithm,

      tbsCertificate: this.sod.certificate.tbs.bytes.toNumberArray(),
      dscSignatureAlgorithm: this.sod.certificate.signatureAlgorithm.name,
      dscSignature: this.sod.certificate.signature.toNumberArray(),

      sodSignature: this.sod.signerInfo.signature.toNumberArray(),
      sodSignatureAlgorithm: this.sod.signerInfo.signatureAlgorithm.name,
    }
  }

  public loadPassport(dg1: Binary, sod: Binary) {
    this.sod = SOD.fromDER(sod)
    this.dg1 = dg1
  }
}

export function getSODContent(passport: PassportViewModel): ASN.SignedData {
  const cert = AsnParser.parse(passport.sod.bytes.toBuffer(), ASN.ContentInfo)
  const signedData = AsnParser.parse(cert.content, ASN.SignedData)
  return signedData
}

export function getEContentHashAlgorithm(passport: PassportViewModel): string {
  const eContent = getEContent(passport)
  const oidOffset = 9
  const oidLength = eContent[oidOffset + 1]
  const oidBytes = eContent.slice(oidOffset, oidOffset + oidLength + 2)
  return HASH_OIDS[decodeOID(oidBytes) as keyof typeof HASH_OIDS] ?? ""
}

export function getEContent(passport: PassportViewModel): number[] {
  const signedData = getSODContent(passport)
  return Array.from(
    new Uint8Array(signedData.encapContentInfo.eContent?.single?.buffer ?? new ArrayBuffer(0)),
  )
}

export function getSignedAttributesHashingAlgorithm(passport: PassportViewModel): string {
  const signedData = getSODContent(passport)
  return HASH_OIDS[signedData.digestAlgorithms[0].algorithm as keyof typeof HASH_OIDS] ?? ""
}

export function getSODCMSVersion(passport: PassportViewModel): string {
  const signedData = getSODContent(passport)
  return signedData.version.toString()
}

export function extractTBS(passport: PassportViewModel): TBSCertificate | null {
  const signedData = getSODContent(passport)
  const tbsCertificate = signedData.certificates
    ? signedData.certificates[0]?.certificate?.tbsCertificate
    : null
  return tbsCertificate ?? null
}

function fromBytesToBigInt(bytes: number[]): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"))
}

function fromArrayBufferToBigInt(buffer: ArrayBuffer): bigint {
  return BigInt("0x" + Buffer.from(buffer).toString("hex"))
}

export function getCurveName(ecParams: ECParameters): string {
  if (ecParams.namedCurve) {
    return CURVE_OIDS[ecParams.namedCurve as keyof typeof CURVE_OIDS] ?? ""
  }
  if (!ecParams.specifiedCurve) {
    return ""
  }
  const a = fromArrayBufferToBigInt(ecParams.specifiedCurve.curve.a)
  const b = fromArrayBufferToBigInt(ecParams.specifiedCurve.curve.b)
  const n = fromArrayBufferToBigInt(ecParams.specifiedCurve.order)
  const p = fromArrayBufferToBigInt(ecParams.specifiedCurve.fieldID.parameters.slice(2))

  if (a == p256.CURVE.a && b == p256.CURVE.b && n == p256.CURVE.n && p == p256.CURVE.Fp.ORDER) {
    return "P-256"
  } else if (
    a == p384.CURVE.a &&
    b == p384.CURVE.b &&
    n == p384.CURVE.n &&
    p == p384.CURVE.Fp.ORDER
  ) {
    return "P-384"
  } else if (
    a == p521.CURVE.a &&
    b == p521.CURVE.b &&
    n == p521.CURVE.n &&
    p == p521.CURVE.Fp.ORDER
  ) {
    return "P-521"
  }

  for (const key in BRAINPOOL_CURVES) {
    if (
      a == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].a &&
      b == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].b &&
      n == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].n &&
      p == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].p
    ) {
      return key
    }
  }

  return `unknown curve`
}

export function getECDSAInfo(subjectPublicKeyInfo: SubjectPublicKeyInfo): {
  curve: string
  publicKey: Uint8Array
} {
  const parsedParams = AsnParser.parse(subjectPublicKeyInfo.algorithm.parameters!, ECParameters)
  return {
    curve: getCurveName(parsedParams),
    publicKey: new Uint8Array(subjectPublicKeyInfo.subjectPublicKey),
  }
}

export function getRSAPSSParams(signatureAlgorithm: AlgorithmIdentifier): {
  hashAlgorithm: DigestAlgorithm
  saltLength: number
  maskGenAlgorithm: string
} {
  const parsedKey = AsnParser.parse(signatureAlgorithm.parameters!, RsaSaPssParams)
  const hashAlgorithm = HASH_OIDS[parsedKey.hashAlgorithm.algorithm as keyof typeof HASH_OIDS] ?? ""
  const maskGenAlgorithm =
    HASH_OIDS[parsedKey.maskGenAlgorithm.algorithm as keyof typeof HASH_OIDS] ?? ""
  return {
    hashAlgorithm: hashAlgorithm.replace("SHA-", "SHA") as DigestAlgorithm,
    saltLength: parsedKey.saltLength,
    maskGenAlgorithm,
  }
}

export function getRSAInfo(subjectPublicKeyInfo: SubjectPublicKeyInfo): {
  modulus: bigint
  exponent: bigint
  type: "pkcs" | "pss"
} {
  const parsedKey = AsnParser.parse(subjectPublicKeyInfo.subjectPublicKey!, RSAPublicKey)
  const type = RSA_OIDS[subjectPublicKeyInfo.algorithm.algorithm as keyof typeof RSA_OIDS] ?? ""
  return {
    modulus: fromArrayBufferToBigInt(parsedKey.modulus),
    exponent: fromArrayBufferToBigInt(parsedKey.publicExponent),
    type: type.includes("pss") ? "pss" : "pkcs",
  }
}

export function getSignatureAlgorithmType(signatureAlgorithm: string): "RSA" | "ECDSA" | "" {
  if (signatureAlgorithm.toLowerCase().includes("rsa")) {
    return "RSA"
  } else if (signatureAlgorithm.toLowerCase().includes("ecdsa")) {
    return "ECDSA"
  }
  return ""
}

export function getSodSignatureAlgorithmType(passport: PassportViewModel): "RSA" | "ECDSA" | "" {
  if (passport.sodSignatureAlgorithm?.toLowerCase().includes("rsa")) {
    return "RSA"
  } else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("ecdsa")) {
    return "ECDSA"
  }
  return ""
}

export function getSodSignatureHashAlgorithm(
  passport: PassportViewModel,
): DigestAlgorithm | undefined {
  if (passport.sodSignatureAlgorithm?.toLowerCase().includes("sha256")) {
    return "SHA256"
  } else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("sha384")) {
    return "SHA384"
  } else if (passport.sodSignatureAlgorithm?.toLowerCase().includes("sha512")) {
    return "SHA512"
  }
}

export function getDSCSignatureAlgorithmType(passport: PassportViewModel): "RSA" | "ECDSA" | "" {
  if (passport.dscSignatureAlgorithm?.toLowerCase().includes("rsa")) {
    return "RSA"
  } else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("ecdsa")) {
    return "ECDSA"
  }
  return ""
}

export function getDSCSignatureHashAlgorithm(
  passport: PassportViewModel,
): DigestAlgorithm | undefined {
  if (passport.dscSignatureAlgorithm?.toLowerCase().includes("sha256")) {
    return "SHA256"
  } else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("sha384")) {
    return "SHA384"
  } else if (passport.dscSignatureAlgorithm?.toLowerCase().includes("sha512")) {
    return "SHA512"
  }
}
