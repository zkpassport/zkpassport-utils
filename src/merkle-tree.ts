import { Binary } from "./binary"
import { LeanIMT } from "@zk-kit/lean-imt"

let bb: any = null
let Fr: any = null

async function initBarretenberg() {
  if (!bb) {
    try {
      const { BarretenbergSync, Fr: FrClass } = await import("@aztec/bb.js")
      bb = await BarretenbergSync.initSingleton()
      Fr = FrClass
    } catch (error) {
      throw new Error("@aztec/bb.js is required for Merkle tree operations. Please install it as a dependency.")
    }
  }
  return { bb, Fr }
}

// NOTE: height is currently not used because we're using a _lean_ imt that doesn't yet support padding
export async function computeMerkleProof(height: number, leaves: Binary[], index: number) {
  if (index < 0 || index >= leaves.length) throw new Error("Invalid index")
  
  const { bb: barretenberg, Fr: FrClass } = await initBarretenberg()
  
  const hash = (a: bigint, b: bigint) =>
    uint8ArrayToBigInt(barretenberg.poseidon2Hash([new FrClass(a), new FrClass(b)]).value)
  const tree = new LeanIMT(
    hash,
    leaves.map((leaf) => leaf.toBigInt()),
  )
  const proof = tree.generateProof(index)
  return {
    root: "0x" + proof.root.toString(16),
    index: proof.index,
    path: proof.siblings.map((x) => "0x" + x.toString(16)),
  }
}

function uint8ArrayToBigInt(uint8Array: Uint8Array): bigint {
  return BigInt(
    `0x${Array.from(uint8Array)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")}`,
  )
}
