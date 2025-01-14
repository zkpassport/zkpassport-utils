import { ProofData } from ".";

/**
 * Convert a date string to a Date object
 * @param strDate - The date string to convert (YYYYMMDD)
 * @returns The Date object
 */
export function convertDateBytesToDate(strDate: string): Date {
    const year = Number(strDate.slice(0, 4))
    const month = Number(strDate.slice(4, 6))
    const day = Number(strDate.slice(6, 8))
    return new Date(year, month - 1, day)
}

export function getMinDateFromProof(proofData: ProofData): Date {
    const dateBytes = proofData.publicInputs.slice(9, 17).map((x) => Number(x) - 48).map((x) => x.toString())
    const date = convertDateBytesToDate(dateBytes.join(""))
    return date
}

export function getMaxDateFromProof(proofData: ProofData): Date {
    const dateBytes = proofData.publicInputs.slice(17, 25).map((x) => Number(x) - 48).map((x) => x.toString())
    const date = convertDateBytesToDate(dateBytes.join(""))
    return date
}
