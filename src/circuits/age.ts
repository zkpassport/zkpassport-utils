import { convertDateBytesToDate, ProofData } from "."

export function getMinAgeFromProof(proofData: ProofData): number {
  return Number(BigInt(proofData.publicInputs[9]))
}

export function getMaxAgeFromProof(proofData: ProofData): number {
  return Number(BigInt(proofData.publicInputs[10]))
}

export function getCurrentDateFromAgeProof(proofData: ProofData): Date {
  const dateBytes = proofData.publicInputs
    .slice(1, 9)
    .map((x) => Number(x) - 48)
    .map((x) => x.toString())
  const date = convertDateBytesToDate(dateBytes.join(""))
  return date
}
