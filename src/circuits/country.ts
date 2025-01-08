import { Alpha3Code } from "i18n-iso-countries";
import { ProofData } from ".";

export function getCountryWeightedSum(country: Alpha3Code): number[] {
  return [country.charCodeAt(0) * 0x10000 + country.charCodeAt(1) * 0x100 + country.charCodeAt(2)]
}

export function getCountryFromWeightedSum(weightedSum: number): Alpha3Code {
  return String.fromCharCode(Math.floor(weightedSum / 0x10000), Math.floor(weightedSum / 0x100) % 256, weightedSum % 256) as Alpha3Code
}

export function getCountryListFromInclusionProof(proofData: ProofData): Alpha3Code[] {
  const countryList = proofData.publicInputs.slice(1, -4)
  const result: Alpha3Code[] = []
  for(let i = 0; i < countryList.length; i += 3) {
    if (Number(countryList[i]) !== 0) {
      result.push(new TextDecoder().decode(new Uint8Array(countryList.slice(i, i + 3).map(Number))) as Alpha3Code)
    }
  }
  return result
}

export function getCountryListFromExclusionProof(proofData: ProofData): Alpha3Code[] {
    const countryList = proofData.publicInputs.slice(1, -4)
    const result: Alpha3Code[] = []
    for(let i = 0; i < countryList.length; i++) {
        if (Number(countryList[i]) !== 0) {
            result.push(getCountryFromWeightedSum(Number(countryList[i])))
        }
    }
    return result
}
