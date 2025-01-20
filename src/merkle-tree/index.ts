import { Binary } from "../binary"
import { hashToFieldAsyncBN254 as poseidon2HashToFieldAsync } from "@zkpassport/poseidon2"
import { AsyncIMT } from "./async-imt"

async function poseidon2(values: any[]) {
  return poseidon2HashToFieldAsync(values.map((v) => BigInt(v)))
}

export async function computeMerkleProof(leaves: Binary[], index: number, height: number) {
  if (index < 0 || index >= leaves.length) throw new Error("Invalid index")
  const zeroValue = 0
  const arity = 2
  const tree = new AsyncIMT(poseidon2, height, arity)
  await tree.initialize(
    zeroValue,
    leaves.map((leaf) => leaf.toBigInt()),
  )
  const proof = tree.createProof(index)
  return {
    root: Binary.from(BigInt(proof.root)).toHex(),
    index: proof.leafIndex,
    path: proof.siblings.flatMap((v) => Binary.from(BigInt(v)).toHex()),
  }
}

export { AsyncIMT }
