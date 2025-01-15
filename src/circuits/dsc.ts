import { ProofData } from ".."

export function getMerkleRootFromDSCProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[0])
}

export function getCommitmentFromDSCProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[1])
}
