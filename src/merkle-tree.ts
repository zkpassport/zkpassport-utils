import { hashToField } from "@zkpassport/poseidon2/bn254"
import { Binary } from "./binary"
import { LeanIMT } from "@zk-kit/lean-imt"

// NOTE: height is currently not used because we're using a _lean_ imt that doesn't yet support padding
export async function computeMerkleProof(height: number, leaves: Binary[], index: number) {
  if (index < 0 || index >= leaves.length) throw new Error("Invalid index")
  
  const hash = (a: bigint, b: bigint) =>
    hashToField([a, b])

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
