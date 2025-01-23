import { Binary } from "./binary"

/**
 * Convert a proof in hex format to an array of fields.
 * @param proof - The proof to convert.
 * @returns An array of fields.
 */
export function proofToFields(proof: string) {
  // Convert hex string to bytes
  const bytes = Buffer.from(proof, "hex")

  // Start from index 4 and chunk into 32-byte segments
  const fields: Buffer[] = []
  for (let i = 4; i < bytes.length; i += 32) {
    fields.push(bytes.subarray(i, i + 32))
  }

  return fields.map((field) => field.toString("hex"))
}

/**
 * Get the number of public inputs from a proof.
 * @param proofAsFields - The proof as an array of fields.
 * @returns The number of public inputs.
 */
export function getNumberOfPublicInputs(proofAsFields: string[]) {
  return parseInt(proofAsFields[1], 16)
}

/**
 * Get the public inputs from a proof.
 * @param proofAsFields - The proof as an array of fields.
 * @returns The public inputs.
 */
export function getPublicInputs(proofAsFields: string[]) {
  const publicInputsNumber = getNumberOfPublicInputs(proofAsFields)
  return proofAsFields.slice(3, publicInputsNumber + 3)
}

/**
 * Get the proof without the public inputs.
 * @param proofAsFields - The proof as an array of fields.
 * @returns The proof without the public inputs.
 */
export function getProofWithoutPublicInputs(proofAsFields: string[]) {
  const publicInputsNumber = getNumberOfPublicInputs(proofAsFields)
  return [...proofAsFields.slice(0, 3), ...proofAsFields.slice(publicInputsNumber + 3)]
}

/**
 * Get the proof data from a proof.
 * @param proof - The proof to get the data from.
 * @returns The proof data.
 */
export function getProofData(proof: string) {
  const proofAsFields = proofToFields(proof)
  const proofWithoutPublicInputs = getProofWithoutPublicInputs(proofAsFields)
  const proofBytes = Buffer.from(proofWithoutPublicInputs.join(""), "hex")
  const publicInputs = getPublicInputs(proofAsFields)
  return {
    proof: Binary.fromHex(proof).slice(0, 4).concat(Binary.fromBuffer(proofBytes)).toUInt8Array(),
    // Make sure it's prefixed with 0x
    publicInputs: publicInputs.map((input) => (input.startsWith("0x") ? input : `0x${input}`)),
  }
}
