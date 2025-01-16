import { Binary } from "./binary"
import { hashToFieldBN254 as poseidon2HashToField } from "@zkpassport/poseidon2"
import { IMT } from "@zk-kit/imt"

function poseidon2(values: any[]) {
  return poseidon2HashToField(values.map((v) => BigInt(v)))
}

export function computeMerkleProof(leaves: Binary[], index: number, height: number) {
  if (index < 0 || index >= leaves.length) throw new Error("Invalid index")
  const zeroValue = 0
  const arity = 2
  const tree = new IMT(
    poseidon2,
    height,
    zeroValue,
    arity,
    leaves.map((leaf) => leaf.toBigInt()),
  )
  const proof = tree.createProof(index)
  return {
    root: Binary.from(BigInt(proof.root)).toHex(),
    index: proof.leafIndex,
    path: proof.siblings.flatMap((v) => Binary.from(BigInt(v)).toHex()),
  }
}
