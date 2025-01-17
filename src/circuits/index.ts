import { CERTIFICATE_REGISTRY_ID, CERT_TYPE_CSC } from "../constants"
import { Binary } from "../binary"
import { hashToFieldBN254 as hashToField } from "@zkpassport/poseidon2"
import { Certificate, ECDSACSCPublicKey, RSACSCPublicKey } from "../types"

export interface ProofData {
  publicInputs: string[]
  proof: Uint8Array | string
}

export function calculatePrivateNullifier(dg1: Binary, sodSig: Binary): Binary {
  return Binary.from(
    hashToField([
      ...Array.from(dg1).map((x) => BigInt(x)),
      ...Array.from(sodSig).map((x) => BigInt(x)),
    ]),
  )
}

export function hashSaltCountryTbs(
  salt: bigint,
  country: string,
  tbs: Binary,
  maxTbsLength: number,
): Binary {
  const result: bigint[] = []
  result.push(salt)
  result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))))
  result.push(...Array.from(tbs.padEnd(maxTbsLength)).map((x) => BigInt(x)))
  return Binary.from(hashToField(result.map((x) => BigInt(x))))
}

export function hashSaltCountrySignedAttrDg1PrivateNullifier(
  salt: bigint,
  country: string,
  paddedSignedAttr: Binary,
  signedAttrSize: bigint,
  dg1: Binary,
  privateNullifier: bigint,
): Binary {
  const result: bigint[] = []
  result.push(salt)
  result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))))
  result.push(...Array.from(paddedSignedAttr).map((x) => BigInt(x)))
  result.push(signedAttrSize)
  result.push(...Array.from(dg1).map((x) => BigInt(x)))
  result.push(privateNullifier)
  return Binary.from(hashToField(result.map((x) => BigInt(x))))
}

export function hashSaltDg1PrivateNullifier(
  salt: bigint,
  dg1: Binary,
  privateNullifier: bigint,
): Binary {
  const result: bigint[] = []
  result.push(salt)
  result.push(...Array.from(dg1).map((x) => BigInt(x)))
  result.push(privateNullifier)
  return Binary.from(hashToField(result.map((x) => BigInt(x))))
}

export function getCertificateLeafHash(
  cert: Certificate,
  options?: { registry_id?: number; cert_type?: number },
): string {
  const registryId = options?.registry_id ?? CERTIFICATE_REGISTRY_ID
  const certType = options?.cert_type ?? CERT_TYPE_CSC

  let publicKey: Binary
  if (cert.public_key.type === "rsaEncryption") {
    publicKey = Binary.from((cert.public_key as RSACSCPublicKey).modulus)
  } else if (cert.public_key.type === "ecPublicKey") {
    publicKey = Binary.from((cert.public_key as ECDSACSCPublicKey).public_key_x).concat(
      Binary.from((cert.public_key as ECDSACSCPublicKey).public_key_y),
    )
  } else {
    throw new Error("Unsupported signature algorithm")
  }
  return Binary.from(
    hashToField([
      BigInt(registryId),
      BigInt(certType),
      ...Array.from(cert.country).map((char: string) => BigInt(char.charCodeAt(0))),
      ...Array.from(publicKey).map((x) => BigInt(x)),
    ]),
  ).toHex()
}

export function getNullifierFromDisclosureProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[proofData.publicInputs.length - 1])
}

export function getServiceSubScopeFromDisclosureProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[proofData.publicInputs.length - 2])
}

export function getServiceScopeFromDisclosureProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[proofData.publicInputs.length - 3])
}

export function getCommitmentInFromDisclosureProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[0])
}

export { DisclosedData, createDisclosedDataRaw } from "./disclose"

export * from "./country"
export * from "./age"
export * from "./date"
export * from "./integrity"
export * from "./id-data"
export * from "./dsc"
