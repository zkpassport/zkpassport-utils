function bufferToField(buf: Uint8Array) {
  return "0x" + Buffer.from(buf).toString("hex").padStart(64, "0")
}

// Converts a serialized UltraHonk verification key into an array of field elements
// See the C++ Barretenberg function to_field_elements() for UltraVerificationKey
export function ultraVkToFields(vkey: Uint8Array): string[] {
  const fields: string[] = []

  const circuit_size = bufferToField(vkey.slice(0, 8)) // uint64
  const num_public_inputs = bufferToField(vkey.slice(8, 16)) // uint64, skipped
  const pub_inputs_offset = bufferToField(vkey.slice(16, 24)) // uint64
  const contains_ipa_claim = bufferToField(vkey.slice(25, 32)) // bool
  // Contains aggregation object (aka contains_pairing_point_accumulator)
  const contains_aggregation_object = bufferToField(vkey.slice(32, 33)) // bool
  // Aggregation object (aka pairing_point_accumulator_indices) See: https://github.com/aztecprotocol/aztec-packages/blob/c53f4cf84c60b8d81cc62d5827ec4408da88cc4e/barretenberg/cpp/src/barretenberg/plonk_honk_shared/types/aggregation_object_type.hpp#L10
  const aggregation_object = vkey.slice(33, 97)
  const ipa_claim_commitment = vkey.slice(97)

  fields.push(circuit_size)
  fields.push(pub_inputs_offset)
  fields.push(contains_ipa_claim)
  fields.push(contains_aggregation_object)
  // Aggregation object
  for (let offset = 0; offset < 64; offset += 4) {
    fields.push(bufferToField(aggregation_object.slice(offset, offset + 4)))
  }
  // Process commitment data (remaining bytes)
  // Each 32-byte commitment is split into two field elements
  for (let offset = 0; offset < ipa_claim_commitment.length; offset += 32) {
    const commitment = ipa_claim_commitment.slice(offset, offset + 32)
    if (commitment.length === 0) break
    // First field element uses bytes 15-31 (17 bytes)
    fields.push(bufferToField(commitment.slice(15, 32)))
    // Second field element uses bytes 0-14 (15 bytes)
    fields.push(bufferToField(commitment.slice(0, 15)))
  }
  return fields
}

/**
 * Get the number of public inputs from a vkey.
 * @param vkey - The vkey to get the number of public inputs from.
 * @returns The number of public inputs.
 */
export function getNumberOfPublicInputsFromVkey(vkey: Uint8Array): number {
  const num_public_inputs = bufferToField(vkey.slice(8, 16))
  return parseInt(num_public_inputs, 16)
}
