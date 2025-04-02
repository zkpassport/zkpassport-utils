import { ECParameters } from "@peculiar/asn1-ecc"
import { p256 } from "@noble/curves/p256"
import { p384 } from "@noble/curves/p384"
import { p521 } from "@noble/curves/p521"
import { BRAINPOOL_CURVES, CURVE_OIDS, HASH_OIDS, RSA_OIDS } from "./constants"
import { AsnParser } from "@peculiar/asn1-schema"
import {
  AuthorityKeyIdentifier,
  PrivateKeyUsagePeriod,
  SubjectKeyIdentifier,
  Certificate as X509Certificate,
} from "@peculiar/asn1-x509"
import { RSAPublicKey, RsaSaPssParams } from "@peculiar/asn1-rsa"
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from "@peculiar/asn1-x509"
import { DigestAlgorithm } from "./types"
import {
  id_authorityKeyIdentifier,
  id_privateKeyUsagePeriod,
  id_subjectKeyIdentifier,
} from "./oids"

export function getCurveName(ecParams: ECParameters): string {
  if (ecParams.namedCurve) {
    return CURVE_OIDS[ecParams.namedCurve as keyof typeof CURVE_OIDS] ?? ""
  }
  if (!ecParams.specifiedCurve) {
    return ""
  }
  const a = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.a).toString("hex")}`)
  const b = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.b).toString("hex")}`)
  const n = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.order).toString("hex")}`)
  const p = BigInt(
    `0x${Buffer.from(ecParams.specifiedCurve.fieldID.parameters.slice(2)).toString("hex")}`,
  )

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

export function getAuthorityKeyId(cert: X509Certificate): string | undefined {
  const authKeyExt = cert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === id_authorityKeyIdentifier,
  )
  if (authKeyExt?.extnValue) {
    try {
      const authKeyId = AsnParser.parse(authKeyExt.extnValue, AuthorityKeyIdentifier)
      const keyId = authKeyId?.keyIdentifier?.buffer
      if (!keyId) return
      return `0x${Buffer.from(keyId).toString("hex")}`
    } catch (error) {
      return
    }
  }
  return
}

export function getSubjectKeyId(cert: X509Certificate): string | undefined {
  const subjKeyExt = cert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === id_subjectKeyIdentifier,
  )
  if (subjKeyExt?.extnValue) {
    try {
      const subjKeyId = AsnParser.parse(subjKeyExt.extnValue, SubjectKeyIdentifier)
      const keyId = subjKeyId?.buffer
      if (!keyId) return
      return `0x${Buffer.from(keyId).toString("hex")}`
    } catch (error) {
      return
    }
  }
  return
}

export function getPrivateKeyUsagePeriod(
  cert: X509Certificate,
): { not_before?: number; not_after?: number } | undefined {
  const pkupExt = cert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === id_privateKeyUsagePeriod,
  )
  if (pkupExt?.extnValue) {
    const pkup = AsnParser.parse(pkupExt.extnValue, PrivateKeyUsagePeriod)
    return {
      not_before: pkup.notBefore ? Math.floor(pkup.notBefore.getTime() / 1000) : undefined,
      not_after: pkup.notAfter ? Math.floor(pkup.notAfter.getTime() / 1000) : undefined,
    }
  }
  return
}

function fromBytesToBigInt(bytes: number[]): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"))
}

function fromArrayBufferToBigInt(buffer: ArrayBuffer): bigint {
  return BigInt("0x" + Buffer.from(buffer).toString("hex"))
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
