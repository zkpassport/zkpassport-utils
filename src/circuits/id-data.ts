import { ProofData } from ".."

export function getCommitmentInFromIDDataProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[0])
}

export function getCommitmentOutFromIDDataProof(proofData: ProofData): bigint {
  return BigInt(proofData.publicInputs[1])
}
