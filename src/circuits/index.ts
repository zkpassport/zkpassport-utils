import { Binary } from "../binary"
import { BB_THREADS, CERT_TYPE_CSC, CERTIFICATE_REGISTRY_ID, TBS_MAX_SIZE } from "../constants"
import { Certificate, ECDSACSCPublicKey, RSACSCPublicKey } from "../types"
import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js"
import { ProofData } from "@noir-lang/types"
import { hashToField } from "@zkpassport/poseidon2/bn254"
import { loadModule } from "@/utils"

// Node.js specific imports
const fs = await loadModule("fs")
const path = await loadModule("path")

let bb: any = null
let Fr: any = null
let UltraHonkBackend: any = null

async function initBarretenberg() {
  if (!bb) {
    try {
      const { BarretenbergSync, Fr: FrClass, UltraHonkBackend: UHBackend } = await import("@aztec/bb.js")
      bb = await BarretenbergSync.initSingleton()
      Fr = FrClass
      UltraHonkBackend = UHBackend
    } catch (error) {
      throw new Error("@aztec/bb.js is required for circuit operations. Please install it as a dependency.")
    }
  }
  return { bb, Fr, UltraHonkBackend }
}

export class Circuit {
  private manifest: CompiledCircuit
  private name: string
  public backend?: any
  public noir?: Noir

  constructor(manifest: CompiledCircuit, name: string) {
    this.manifest = manifest
    this.name = name
  }

  async init() {
    const { UltraHonkBackend: UHBackend } = await initBarretenberg()
    this.backend = new UHBackend(this.manifest.bytecode, {
      threads: BB_THREADS,
    })
    this.noir = new Noir(this.manifest)
  }

  async solve(inputs: InputMap): Promise<Uint8Array> {
    await this.init()
    const { witness } = await this.noir!.execute(inputs)
    if (!witness) throw new Error("Error solving witness")
    return witness
  }

  async prove(inputs: InputMap, options?: { witness?: Uint8Array }): Promise<ProofData> {
    await this.init()
    const witness = options?.witness ?? (await this.solve(inputs))
    const proof = await this.backend!.generateProof(witness)
    return proof
  }

  async proveRecursiveProof(inputs: InputMap): Promise<{ proof: ProofData; artifacts: any }> {
    const proof = await this.prove(inputs)
    if (!this.backend) throw new Error("Backend not initialized")
    const artifacts = await this.backend.generateRecursiveProofArtifacts(
      proof.proof,
      proof.publicInputs.length,
    )
    return { proof, artifacts }
  }

  async verify(proof: ProofData) {
    await this.init()
    if (!this.backend) throw new Error("Backend not initialized")
    return await this.backend.verifyProof(proof)
  }

  async getVerificationKey() {
    await this.init()
    if (!this.backend) throw new Error("Backend not initialized")
    return await this.backend.getVerificationKey()
  }

  static from(fileName: string): Circuit {
    if (!path) throw new Error("Path is not available in this environment") 
    const isFullPath = path.isAbsolute(fileName) || fileName.includes("/")
    const circuitPath = isFullPath ? fileName : path.resolve(`target/${fileName}.json`)
    try {
      if (!fs) throw new Error("Read file sync is not available in this environment")
      const manifest = JSON.parse(fs.readFileSync(circuitPath, "utf-8"))
      const name = path.basename(fileName, ".json")
      return new Circuit(manifest, name)
    } catch (error) {
      if (error instanceof Error && error.name === "ENOENT") {
        throw new Error(`No such file: target/${fileName}.json`)
      }
      throw error
    }
  }

  getName(): string {
    return this.name
  }
}

export function calculatePrivateNullifier(dg1: Binary, sodSig: Binary): Binary {
  return Binary.from(
   hashToField([
    ...Array.from(dg1).map((x) => BigInt(x)),
    ...Array.from(sodSig).map((x) => BigInt(x)),
    ])
  )
}

export function hashSaltCountryTbs(salt: bigint, country: string, tbs: Binary): Binary {
  const result: bigint[] = []
  result.push(salt)
  result.push(...country.split("").map((x) => BigInt(x.charCodeAt(0))))
  result.push(...Array.from(tbs.padEnd(TBS_MAX_SIZE)).map((x) => BigInt(x)))
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
    publicKey = Binary.from((cert.public_key as ECDSACSCPublicKey).public_key_x)
  } else {
    throw new Error("Unsupported signature algorithm")
  }
  return Binary.from(
    hashToField([
        BigInt(registryId),
        BigInt(certType),
        ...Array.from(cert.country).map((char: string) => BigInt(char.charCodeAt(0))),
        ...Array.from(publicKey).map((x) => BigInt(x)),
      ])
  ).toHex()
}


export { DisclosedData, createDisclosedDataRaw } from "@/circuits/disclose";