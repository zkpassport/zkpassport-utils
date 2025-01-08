import { ProofData } from ".";

export function getMinAgeFromProof(proofData: ProofData): number {
  return Number(BigInt(proofData.publicInputs[9]))
}

export function getMaxAgeFromProof(proofData: ProofData): number {
  return Number(BigInt(proofData.publicInputs[10]))
}
