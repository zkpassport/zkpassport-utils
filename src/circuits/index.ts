import { CERTIFICATE_REGISTRY_ID, CERT_TYPE_CSC } from "../constants"
import { Binary } from "../binary"
import { hashToFieldAsyncBN254 as hashToField } from "@zkpassport/poseidon2"
import { Certificate, ECDSACSCPublicKey, PackagedCircuit, RSACSCPublicKey } from "../types"

export interface ProofData {
  publicInputs: string[]
  proof: Uint8Array | string
}

export async function calculatePrivateNullifier(dg1: Binary, sodSig: Binary): Promise<Binary> {
  return Binary.from(
    await hashToField([
      ...Array.from(dg1).map((x) => BigInt(x)),
      ...Array.from(sodSig).map((x) => BigInt(x)),
    ]),
  )
}

export async function hashSaltCountryTbs(
  salt: bigint,
  country: string,
  tbs: Binary,
  maxTbsLength: number,
): Promise<Binary> {
  const result: bigint[] = []
  result.push(salt)
  result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))))
  result.push(...Array.from(tbs.padEnd(maxTbsLength)).map((x) => BigInt(x)))
  return Binary.from(await hashToField(result.map((x) => BigInt(x))))
}

export async function hashSaltCountrySignedAttrDg1PrivateNullifier(
  salt: bigint,
  country: string,
  paddedSignedAttr: Binary,
  signedAttrSize: bigint,
  dg1: Binary,
  privateNullifier: bigint,
): Promise<Binary> {
  const result: bigint[] = []
  result.push(salt)
  result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))))
  result.push(...Array.from(paddedSignedAttr).map((x) => BigInt(x)))
  result.push(signedAttrSize)
  result.push(...Array.from(dg1).map((x) => BigInt(x)))
  result.push(privateNullifier)
  return Binary.from(await hashToField(result.map((x) => BigInt(x))))
}

export async function hashSaltDg1PrivateNullifier(
  salt: bigint,
  dg1: Binary,
  privateNullifier: bigint,
): Promise<Binary> {
  const result: bigint[] = []
  result.push(salt)
  result.push(...Array.from(dg1).map((x) => BigInt(x)))
  result.push(privateNullifier)
  return Binary.from(await hashToField(result.map((x) => BigInt(x))))
}

export async function getCertificateLeafHash(
  cert: Certificate,
  options?: { registry_id?: number; cert_type?: number },
): Promise<string> {
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
    await hashToField([
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

export async function getHostedPackagedCircuitByNameAndHash(
  name: string,
  vkeyHash: string,
): Promise<PackagedCircuit> {
  const response = await fetch(
    `https://circuits.zkpassport.id/artifacts/${name}_${vkeyHash
      .replace("0x", "")
      .substring(0, 16)}.json.gz`,
  )
  const circuit = await response.json()
  return circuit
}

export async function getHostedPackagedCircuitByVkeyHash(
  vkeyHash: string,
): Promise<PackagedCircuit> {
  const response = await fetch(
    `https://circuits.zkpassport.id/hashes/${vkeyHash.replace("0x", "")}.json.gz`,
  )
  const circuit = await response.json()
  return circuit
}

export async function getHostedPackagedCircuitByName(
  version: `${number}.${number}.${number}`,
  name: string,
): Promise<PackagedCircuit> {
  const response = await fetch(`https://circuits.zkpassport.id/versions/${version}/${name}.json.gz`)
  const circuit = await response.json()
  return circuit
}

export { DisclosedData, createDisclosedDataRaw, formatName } from "./disclose"

export * from "./country"
export * from "./age"
export * from "./date"
export * from "./integrity"
export * from "./id-data"
export * from "./dsc"
export * from "./vkey"
