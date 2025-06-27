import { format } from "date-fns"
import { Alpha3Code } from "i18n-iso-countries"
import {
  calculateAge,
  getAgeCircuitInputs,
  getBirthdateCircuitInputs,
  getCscaForPassport,
  getDSCCircuitInputs,
  getDSCCountry,
  getDiscloseCircuitInputs,
  getExpiryDateCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
  getIssuingCountryExclusionCircuitInputs,
  getIssuingCountryInclusionCircuitInputs,
  getNationalityExclusionCircuitInputs,
  getNationalityInclusionCircuitInputs,
  isCscaSupported,
  isDSCSupported,
  isIDSupported,
} from "../src/circuit-matcher"
import { getCountryWeightedSum } from "../src/circuits/country"
import { HashAlgorithm, PackagedCertificate, Query } from "../src/types"
import { rightPadArrayWithZeros, rightPadCountryCodeArray } from "../src/utils"
import rootCerts from "./fixtures/root-certs.json"
import { PASSPORTS } from "./fixtures/passports"
import * as fs from "fs"
import * as path from "path"
import { Binary, getCurveName, getDSCSignatureHashAlgorithm } from "../src"
import { DSC } from "../src/passport/dsc"
import { AsnParser } from "@peculiar/asn1-schema"
import { AuthorityKeyIdentifier } from "@peculiar/asn1-x509"
import { ECParameters } from "@peculiar/asn1-ecc"
import { getFirstNameRange, getFullNameRange, getLastNameRange } from "../src/passport/getters"

function getDSCs() {
  const dscDir = path.join(__dirname, "fixtures", "dsc")
  const files = fs.readdirSync(dscDir)

  return files
    .filter((file) => file.endsWith(".der"))
    .map((file) => {
      const filePath = path.join(dscDir, file)
      const content = fs.readFileSync(filePath)
      return DSC.fromDER(Binary.from(content))
    })
}

const EXPECTED_NULLIFIER = "0x2fa89c11a1035d4eed0a92e5b0bbc5d0ab78a5749cf3b402f8a2896b9cc8b8a3";

const SALT = 1n;
const EXPECTED_SALT = "0x1";
const SERVICE_SCOPE = 2n;
const EXPECTED_SERVICE_SCOPE = "0x2";
const SERVICE_SUBSCOPE = 3n;
const EXPECTED_SERVICE_SUBSCOPE = "0x3";

describe("Circuit Matcher - General", () => {

  it("should detect if CSCA certificate is supported", () => {
    const certificates = rootCerts.certificates
    let totalUnsupported = 0
    for (const certificate of certificates) {
      const result = isCscaSupported(certificate as PackagedCertificate)
      const isUnsupportedHashAlgorithm = (certificate.hash_algorithm as HashAlgorithm) === "SHA-224"
      const isUnsupportedExponent =
        certificate.public_key.type === "RSA" &&
        certificate.public_key.exponent !== 65537 &&
        certificate.public_key.exponent !== 3
      const isUnsupportedKeySize =
        certificate.public_key.type === "RSA" &&
        certificate.public_key.key_size !== 1024 &&
        certificate.public_key.key_size !== 2048 &&
        certificate.public_key.key_size !== 3072 &&
        certificate.public_key.key_size !== 4096
      const isUnsupported =
        isUnsupportedHashAlgorithm || isUnsupportedExponent || isUnsupportedKeySize
      if (isUnsupported) {
        totalUnsupported++
      }
      expect(isUnsupported).toBe(!result)
    }
    console.log(`Total unsupported CSCs: ${totalUnsupported} out of ${certificates.length}`)
  })

  // Skipped because it requires the DSC list which is not commited to the repo
  it.skip("should find the CSCs of all the DSCs", () => {
    const dscs = getDSCs()
    const expectedUnknownCSCSubjectKeyIdentifiers = [
      "45728821c8fbff1153455807ad09ed5e868035e8",
      "0654b2b864ec78aa4675f9110634ecdac2a5b4af",
      "a775af64b440e8dd386f2f002280ecedd19d1b97",
    ]
    const unknownCSCSubjectKeyIdentifiers: string[] = []
    const unknownCSCsCountries: string[] = []
    const supportedDSCs: DSC[] = []
    for (const dsc of dscs) {
      if (dsc.tbs.validity.notAfter.getTime() < Date.now()) {
        continue
      }
      const isSupported = isDSCSupported(dsc)
      if (isSupported) {
        supportedDSCs.push(dsc)
      }
      const result = getCscaForPassport(dsc, rootCerts.certificates as PackagedCertificate[])
      if (!result) {
        const akiBuffer = dsc.tbs.extensions.get("authorityKeyIdentifier")?.value.toBuffer()
        if (akiBuffer) {
          const parsed = AsnParser.parse(akiBuffer, AuthorityKeyIdentifier)
          if (parsed?.keyIdentifier?.buffer) {
            const authorityKeyIdentifier = Binary.from(parsed.keyIdentifier.buffer)
              .toHex()
              .replace("0x", "")
            unknownCSCSubjectKeyIdentifiers.push(authorityKeyIdentifier)
          }
        }
        const country = getDSCCountry(dsc)
        if (country) {
          unknownCSCsCountries.push(country)
        }
      }
    }
    console.log(
      `Total DSCs without known CSCs: ${unknownCSCSubjectKeyIdentifiers.length} out of ${dscs.length}`,
    )
    const uniqueUnknownCSCSubjectKeyIdentifiers = Array.from(
      new Set(unknownCSCSubjectKeyIdentifiers),
    )
    const uniqueUnknownCSCsCountries = Array.from(new Set(unknownCSCsCountries))
    console.log(
      `Total unique unknown CSC subject key identifiers: ${uniqueUnknownCSCSubjectKeyIdentifiers.length}`,
    )
    console.log(JSON.stringify(uniqueUnknownCSCSubjectKeyIdentifiers))
    console.log(`Total unique unknown CSC countries: ${uniqueUnknownCSCsCountries.length}`)
    console.log(JSON.stringify(uniqueUnknownCSCsCountries))
    console.log(
      `Hash algorithms: ${JSON.stringify(Array.from(new Set(supportedDSCs.map((x) => getDSCSignatureHashAlgorithm(x)))))}`,
    )
    console.log(
      `Signature algorithms: ${JSON.stringify(
        Array.from(new Set(supportedDSCs.map((x) => x.signatureAlgorithm.name))),
      )}`,
    )
    console.log(
      `Curves: ${JSON.stringify(
        Array.from(
          new Set(
            supportedDSCs.map((x) =>
              x.tbs.subjectPublicKeyInfo.signatureAlgorithm.name.toLowerCase().includes("ec") &&
              x.tbs.subjectPublicKeyInfo.signatureAlgorithm.parameters &&
              x.tbs.subjectPublicKeyInfo.signatureAlgorithm.parameters.toBuffer().length > 0
                ? getCurveName(
                    AsnParser.parse(
                      x.tbs.subjectPublicKeyInfo.signatureAlgorithm.parameters.toBuffer(),
                      ECParameters,
                    ),
                  )
                : "",
            ),
          ),
        ),
      )}`,
    )
    console.log(`Total supported DSCs: ${supportedDSCs.length}`)
    console.log(
      JSON.stringify(Array.from(new Set(supportedDSCs.map((x) => getDSCCountry(x)))).sort()),
    )
    expect(uniqueUnknownCSCSubjectKeyIdentifiers).toEqual(expectedUnknownCSCSubjectKeyIdentifiers)
  })
})

describe("Circuit Matcher - RSA", () => {
  it("should detected if ID is supported", () => {
    const result = isIDSupported(PASSPORTS.john)
    expect(result).toBe(true)
  })

  it("should get the correct CSCA for the passport", () => {
    const result = getCscaForPassport(
      PASSPORTS.john.sod.certificate,
      rootCerts.certificates as PackagedCertificate[],
    )
    expect(result).toEqual(
      rootCerts.certificates.find((x) => x.country === "ZKR" && x.signature_algorithm === "RSA"),
    )
  })

  it("should get the correct DSC circuit inputs", async () => {
    const result = await getDSCCircuitInputs(
      PASSPORTS.john,
      1n,
      rootCerts.certificates as PackagedCertificate[],
    )
    expect(result).toEqual({
      certificate_registry_root: rootCerts.serialised[rootCerts.serialised.length - 1][0],
      certificate_registry_index: 251,
      certificate_registry_hash_path: [
        "0x1ee021b28c01808e2594a16fa037d44a76de9e0a7b818a6696b9683c28b59057",
        "0x046a7e915a03ea3aa527dec0799c38e7e278e8110734b8e33a0fb1b453260387",
        "0x1f179eb8fca43bdfcd9690b285f9fb3eaedb65be465d60408b4d9b9db92f5e31",
        "0x1e79b1c83dae5ebaa403ad68bb5f802ca6ce44807aea32c344e2f59535961e21",
        "0x1efeca1db2e65d3933292c3e034951160333fee39d41fb73f19080846dc83a92",
        "0x05414872b7911beb4e6bbe7a15a0cabdd32bfc14f13f391e069a9ed1643439a6",
        "0x086cb4f43d2bd628ae1323f6d3eb9c8caf388e7643bcb9b303b2fb9289fce7b7",
        "0x1f0ea7762d5549549406bb021a403a09f0116f135053caf4f8ae9e9e65039b8c",
        "0x2ee0fc08b841723ee693af3025a1478e0f9e30429590712bca8da35b96310410",
        "0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972",
        "0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686",
        "0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7",
        "0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73",
        "0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1",
        "0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a",
        "0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9",
      ],
      certificate_tags: "0x0",
      certificate_type: "0x1",
      country: "ZKR",
      salt: EXPECTED_SALT,
      tbs_certificate: rightPadArrayWithZeros(
        PASSPORTS.john.sod.certificate.tbs.bytes.toNumberArray(),
        700,
      ),
      tbs_certificate_len: 582,
      dsc_signature: PASSPORTS.john.sod.certificate.signature.toNumberArray(),
      csc_pubkey: [
        248, 49, 245, 49, 134, 64, 78, 179, 47, 178, 82, 126, 19, 229, 209, 152, 237, 167, 236, 246,
        86, 119, 34, 191, 211, 111, 112, 65, 64, 49, 155, 81, 182, 44, 213, 36, 96, 11, 21, 152,
        125, 87, 98, 168, 153, 235, 210, 91, 60, 52, 184, 27, 37, 251, 204, 230, 20, 150, 76, 232,
        197, 14, 167, 228, 71, 67, 240, 125, 36, 160, 247, 102, 173, 50, 18, 83, 19, 128, 107, 149,
        217, 101, 75, 73, 55, 192, 6, 169, 226, 236, 45, 61, 45, 216, 231, 100, 224, 60, 127, 20,
        29, 216, 139, 49, 90, 240, 86, 74, 138, 30, 107, 136, 44, 149, 77, 157, 100, 226, 121, 137,
        50, 254, 91, 179, 211, 46, 138, 46, 148, 188, 31, 105, 192, 93, 103, 183, 49, 179, 153, 43,
        2, 21, 45, 66, 240, 210, 139, 64, 22, 188, 116, 116, 202, 150, 53, 116, 170, 160, 103, 112,
        87, 95, 235, 110, 223, 155, 180, 154, 218, 151, 198, 160, 210, 27, 136, 236, 7, 92, 75, 139,
        172, 52, 194, 4, 182, 98, 95, 191, 216, 250, 166, 238, 206, 60, 145, 235, 5, 228, 40, 205,
        119, 118, 128, 141, 16, 174, 210, 232, 116, 182, 26, 80, 29, 192, 184, 139, 115, 250, 83,
        115, 175, 96, 53, 5, 45, 153, 147, 192, 89, 193, 173, 15, 138, 250, 69, 130, 221, 180, 182,
        175, 212, 84, 17, 99, 184, 221, 3, 182, 43, 64, 87, 73, 218, 234, 77, 87,
      ],
      csc_pubkey_redc_param: [
        16, 128, 205, 249, 236, 27, 125, 199, 140, 153, 23, 150, 236, 212, 75, 83, 237, 68, 216, 38,
        212, 120, 230, 234, 48, 15, 182, 204, 29, 60, 131, 246, 168, 199, 219, 148, 63, 166, 72, 72,
        74, 164, 164, 180, 62, 197, 67, 44, 116, 71, 210, 189, 122, 183, 216, 210, 237, 222, 187, 8,
        78, 51, 33, 8, 79, 98, 136, 116, 161, 63, 148, 130, 37, 182, 207, 41, 71, 19, 251, 6, 34,
        130, 219, 16, 111, 59, 237, 58, 247, 84, 146, 37, 69, 67, 179, 240, 219, 235, 45, 68, 130,
        236, 106, 2, 141, 117, 167, 127, 43, 60, 151, 108, 50, 148, 65, 46, 103, 212, 71, 17, 19,
        105, 224, 234, 237, 214, 102, 190, 216, 163, 11, 217, 33, 189, 122, 180, 133, 176, 90, 2,
        215, 73, 130, 168, 223, 1, 197, 160, 199, 123, 50, 138, 2, 15, 231, 4, 108, 67, 245, 19,
        134, 223, 222, 41, 74, 156, 51, 156, 218, 11, 2, 87, 175, 198, 244, 101, 240, 166, 225, 36,
        176, 65, 86, 48, 63, 244, 124, 39, 86, 239, 190, 173, 234, 21, 195, 20, 200, 72, 212, 42,
        118, 21, 72, 204, 83, 210, 5, 73, 78, 217, 110, 25, 5, 203, 234, 232, 198, 228, 39, 195,
        127, 191, 131, 84, 167, 247, 207, 190, 140, 34, 100, 18, 57, 217, 172, 229, 206, 199, 127,
        69, 114, 173, 18, 116, 85, 147, 110, 175, 128, 173, 176, 234, 234, 179, 232, 160, 56,
      ],
      exponent: 65537,
    })
  })

  it("should get the correct ID circuit inputs", async () => {
    const result = await getIDDataCircuitInputs(PASSPORTS.john, SALT, SALT)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      signed_attributes: rightPadArrayWithZeros(
        PASSPORTS.john.sod.signerInfo.signedAttrs.bytes.toNumberArray(),
        200,
      ),
      signed_attributes_size: 104,
      comm_in: "0x1e7ec73a70d9bee5e4f770027cbc1a8a8305ddba417d3401ba933abf90bfbec1",
      salt_in: EXPECTED_SALT,
      salt_out: EXPECTED_SALT,
      dsc_pubkey: [
        183, 242, 238, 143, 100, 36, 214, 7, 217, 1, 216, 190, 216, 130, 126, 226, 178, 25, 248, 13,
        172, 64, 0, 228, 21, 64, 135, 159, 123, 68, 153, 193, 34, 233, 143, 111, 226, 242, 149, 60,
        149, 115, 101, 129, 164, 136, 236, 179, 26, 245, 220, 104, 62, 123, 103, 134, 133, 33, 162,
        169, 119, 237, 225, 110, 188, 102, 83, 165, 240, 102, 99, 233, 148, 236, 63, 219, 119, 152,
        72, 135, 26, 130, 239, 19, 248, 118, 180, 251, 12, 175, 52, 103, 237, 255, 29, 174, 151, 11,
        218, 216, 249, 215, 158, 57, 109, 143, 15, 161, 190, 200, 10, 165, 14, 149, 32, 104, 174,
        24, 44, 163, 132, 207, 248, 234, 172, 206, 25, 200, 169, 31, 21, 135, 84, 166, 168, 198, 42,
        57, 146, 157, 132, 158, 209, 72, 132, 243, 135, 9, 251, 253, 86, 189, 3, 51, 170, 153, 252,
        170, 232, 134, 32, 228, 36, 243, 143, 168, 211, 127, 67, 1, 37, 69, 63, 197, 17, 167, 246,
        188, 214, 20, 80, 53, 21, 129, 84, 0, 108, 139, 231, 27, 249, 22, 35, 27, 227, 37, 112, 219,
        148, 158, 179, 51, 37, 45, 145, 69, 116, 228, 161, 5, 13, 42, 122, 142, 14, 4, 93, 22, 70,
        171, 206, 69, 161, 161, 62, 240, 160, 140, 133, 154, 64, 244, 252, 237, 250, 168, 2, 103,
        197, 251, 154, 172, 189, 117, 93, 167, 237, 51, 217, 74, 225, 178, 212, 188, 219, 231,
      ],
      exponent: 65537,
      sod_signature: PASSPORTS.john.sod.signerInfo.signature.toNumberArray(),
      dsc_pubkey_redc_param: [
        22, 68, 93, 51, 146, 119, 200, 66, 91, 4, 139, 219, 211, 238, 244, 80, 172, 237, 63, 200,
        201, 255, 143, 95, 133, 21, 198, 238, 249, 191, 44, 20, 195, 124, 130, 48, 218, 87, 25, 35,
        148, 240, 137, 79, 16, 220, 88, 104, 16, 172, 53, 242, 255, 71, 108, 14, 33, 24, 190, 49,
        27, 127, 247, 168, 68, 3, 49, 43, 230, 200, 246, 89, 72, 116, 210, 103, 180, 245, 163, 26,
        165, 186, 189, 155, 178, 169, 68, 169, 80, 123, 220, 223, 214, 29, 60, 173, 234, 225, 167,
        152, 98, 169, 20, 186, 101, 131, 241, 108, 3, 101, 44, 164, 56, 51, 107, 39, 107, 32, 84,
        105, 92, 13, 50, 168, 147, 125, 42, 179, 15, 53, 160, 203, 50, 10, 209, 1, 110, 138, 1, 176,
        226, 18, 210, 74, 187, 156, 225, 170, 70, 202, 170, 96, 75, 218, 207, 224, 90, 228, 110,
        104, 21, 62, 109, 117, 182, 242, 219, 35, 0, 216, 250, 95, 178, 73, 192, 56, 107, 219, 141,
        158, 64, 97, 7, 41, 20, 0, 22, 1, 68, 46, 145, 107, 244, 168, 85, 198, 232, 9, 28, 143, 33,
        188, 163, 187, 163, 168, 79, 59, 117, 175, 71, 232, 133, 27, 58, 196, 190, 124, 46, 253, 7,
        234, 196, 93, 211, 101, 180, 103, 120, 132, 124, 71, 169, 77, 94, 147, 235, 0, 74, 214, 230,
        58, 5, 158, 123, 1, 250, 108, 41, 204, 143, 203, 85, 63, 227, 173, 14,
      ],
      tbs_certificate: rightPadArrayWithZeros(
        PASSPORTS.john.sod.certificate.tbs.bytes.toNumberArray(),
        700,
      ),
      pubkey_offset_in_tbs: 199,
    })
  })

  it("should get the right country code from DSC", () => {
    const result = getDSCCountry(PASSPORTS.john.sod.certificate)
    expect(result).toBe("ZKR")
  })

  it("should get the right integrity check circuit inputs", async () => {
    const result = await getIntegrityCheckCircuitInputs(PASSPORTS.john, SALT, SALT)
    expect(result).toEqual({
      current_date: format(new Date(), "yyyyMMdd"),
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      signed_attributes: rightPadArrayWithZeros(
        PASSPORTS.john.sod.signerInfo.signedAttrs.bytes.toNumberArray(),
        200,
      ),
      signed_attributes_size: 104,
      e_content: rightPadArrayWithZeros(
        PASSPORTS.john.sod.encapContentInfo.eContent.bytes.toNumberArray(),
        700,
      ),
      e_content_size: 98,
      dg1_offset_in_e_content: 27,
      comm_in: "0x15c55784d6e98efd7bef72ffd4137ff083364b8d4a56576c0ec5e47a5c34feaa",
      private_nullifier: EXPECTED_NULLIFIER,
      salt_in: EXPECTED_SALT,
      salt_out: EXPECTED_SALT,
    })
  })

  it("should get the correct first name range", () => {
    const result = getFirstNameRange(PASSPORTS.john)
    expect(result).toEqual([10, 16])
  })

  it("should get the correct last name range", () => {
    const result = getLastNameRange(PASSPORTS.john)
    // There's overlap with the first name range as the angle brackets are included
    expect(result).toEqual([5, 12])
  })

  it("should get the correct full name range", () => {
    const result = getFullNameRange(PASSPORTS.john)
    expect(result).toEqual([5, 44])
  })

  it("should get the correct disclose circuit inputs", async () => {
    const query: Query = {
      firstname: { disclose: true },
      lastname: { disclose: true },
      birthdate: { disclose: true },
      nationality: { disclose: true },
      issuing_country: { disclose: true },
    }

    const result = await getDiscloseCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      disclose_mask: [
        0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ],
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should calculate the correct age from passport", () => {
    const result = calculateAge(PASSPORTS.john)
    expect(result).toBe(29)
  })

  it("should get the correct age circuit inputs", async () => {
    const query: Query = {
      age: { gte: 18 },
    }
    const result = await getAgeCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      current_date: format(new Date(), "yyyyMMdd"),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
      min_age_required: 18,
      max_age_required: 0,
    })
  })

  it("should get the correct nationality inclusion circuit inputs", async () => {
    const query: Query = {
      nationality: { in: ["ZKR", "FRA", "GBR", "USA"] },
    }
    const result = await getNationalityInclusionCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      country_list: rightPadCountryCodeArray(["ZKR", "FRA", "GBR", "USA"], 200),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct nationality exclusion circuit inputs", async () => {
    const query: Query = {
      nationality: { out: ["FRA", "USA", "GBR"] },
    }
    const result = await getNationalityExclusionCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      // Notice how the country code are sorted compared to above
      country_list: rightPadCountryCodeArray(["FRA", "GBR", "USA"], 200).map((country) =>
        getCountryWeightedSum(country as Alpha3Code),
      ),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct issuing country inclusion circuit inputs", async () => {
    const query: Query = {
      issuing_country: { in: ["ZKR", "FRA", "GBR", "USA"] },
    }
    const result = await getIssuingCountryInclusionCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      country_list: rightPadCountryCodeArray(["ZKR", "FRA", "GBR", "USA"], 200),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct issuing country exclusion circuit inputs", async () => {
    const query: Query = {
      issuing_country: { out: ["FRA", "USA", "GBR"] },
    }
    const result = await getIssuingCountryExclusionCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      country_list: rightPadCountryCodeArray(["FRA", "GBR", "USA"], 200).map((country) =>
        getCountryWeightedSum(country as Alpha3Code),
      ),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct birthdate circuit inputs", async () => {
    const query: Query = {
      birthdate: { gte: new Date("1980-01-01"), lte: new Date("1990-01-01") },
    }
    const result = await getBirthdateCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      current_date: format(new Date(), "yyyyMMdd"),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
      min_date: "19800101",
      max_date: "19900101",
    })
  })

  it("should get the correct expiry date circuit inputs", async () => {
    const query: Query = {
      expiry_date: { gte: new Date("2025-01-01"), lte: new Date("2035-12-31") },
    }
    const result = await getExpiryDateCircuitInputs(PASSPORTS.john, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.john.dataGroups[0].value, 95),
      current_date: format(new Date(), "yyyyMMdd"),
      comm_in: "0x2a0283e2f98b06cca0b5c908b69c344f87d129401589571aaa574f2151308d5e",
      private_nullifier: EXPECTED_NULLIFIER,
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
      min_date: "20250101",
      max_date: "20351231",
    })
  })
})

describe("Circuit Matcher - ECDSA", () => {
  it("should detected if ID is supported", () => {
    const result = isIDSupported(PASSPORTS.mary)
    expect(result).toBe(true)
  })

  it("should get the correct CSCA for the passport", () => {
    const result = getCscaForPassport(
      PASSPORTS.mary.sod.certificate,
      rootCerts.certificates as PackagedCertificate[],
    )
    expect(result).toEqual(
      rootCerts.certificates.find((x) => x.country === "ZKR" && x.signature_algorithm === "ECDSA"),
    )
  })

  it("should get the correct DSC circuit inputs", async () => {
    const result = await getDSCCircuitInputs(
      PASSPORTS.mary,
      1n,
      rootCerts.certificates as PackagedCertificate[],
    )
    expect(result).toEqual({
      certificate_registry_root: rootCerts.serialised[rootCerts.serialised.length - 1][0],
      certificate_registry_index: 288,
      certificate_registry_hash_path: [
        "0x2279e0b835e985091a284d1a08934336ee251dd2d4d79a1509b71c6fac682561",
        "0x04b369f24cd99ec59cd06e8cc045493cbf760ba8e48fc8b89cf5c349245ea439",
        "0x213e025fd360844246b83b8c0e787023735909d5829e57bc9821e7eedc8c8c81",
        "0x14e82e2e112278557a965d517a8ddd5b0475850bcbd12f9ec643a6b0718e1c61",
        "0x02a6a89a1b30d682c064c5e1fa15d85123aa51aff4a09452e0c8a7cb9b872dca",
        "0x302241961f17e2843700475b185eb6beeac03ef75fc2c85d64f395b705b953cd",
        "0x044eb2aef3c14e0d81a5cc9758865a58b7c052bdcb811310b5e9b7c6e70c292f",
        "0x249ad951ce3a6216055a04eb6d910cdcc798fef5f36e0e694d9ba35f5145d78f",
        "0x163621253979894bde89285410fa47be0e6edc62adf7479cbaa31119bece9edd",
        "0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972",
        "0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686",
        "0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7",
        "0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73",
        "0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1",
        "0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a",
        "0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9",
      ],
      certificate_tags: "0x0",
      certificate_type: "0x1",
      country: "ZKR",
      salt: EXPECTED_SALT,
      csc_pubkey_x: [
        100, 67, 3, 43, 184, 208, 212, 7, 28, 252, 194, 241, 65, 191, 163, 215, 48, 51, 138, 76,
        143, 69, 163, 224, 28, 89, 218, 77, 111, 77, 145, 220,
      ],
      csc_pubkey_y: [
        174, 84, 95, 24, 151, 163, 101, 170, 23, 62, 235, 85, 217, 12, 135, 137, 23, 129, 89, 160,
        8, 154, 151, 127, 22, 55, 93, 197, 145, 218, 255, 163,
      ],
      dsc_signature: [
        ...PASSPORTS.mary.sod.certificate.signature.toNumberArray().slice(4, 36)!,
        ...PASSPORTS.mary.sod.certificate.signature.toNumberArray().slice(38)!,
      ],
      tbs_certificate: rightPadArrayWithZeros(
        PASSPORTS.mary.sod.certificate.tbs.bytes.toNumberArray(),
        700,
      ),
      tbs_certificate_len: 376,
    })
  })

  it("should get the correct ID circuit inputs", async () => {
    const result = await getIDDataCircuitInputs(PASSPORTS.mary, SALT, SALT)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      signed_attributes: rightPadArrayWithZeros(
        PASSPORTS.mary.sod.signerInfo.signedAttrs.bytes.toNumberArray(),
        200,
      ),
      signed_attributes_size: 104,
      comm_in: "0x04befe4fa43a4bcfb052a6de7b9745a09f284aabd0d79e7ee6c461e75f70b7af",
      salt_in: EXPECTED_SALT,
      salt_out: EXPECTED_SALT,
      tbs_certificate: rightPadArrayWithZeros(
        PASSPORTS.mary.sod.certificate.tbs.bytes.toNumberArray(),
        700,
      ),
      pubkey_offset_in_tbs: 190,
      dsc_pubkey_x: [
        38, 197, 165, 50, 70, 123, 24, 161, 149, 121, 124, 15, 43, 188, 231, 62, 245, 182, 9, 243,
        33, 210, 173, 170, 110, 115, 18, 210, 168, 171, 190, 216,
      ],
      dsc_pubkey_y: [
        180, 251, 221, 42, 12, 191, 223, 2, 98, 97, 236, 120, 27, 132, 144, 43, 43, 187, 100, 199,
        222, 180, 166, 185, 133, 43, 134, 225, 103, 129, 152, 86,
      ],
      sod_signature: PASSPORTS.mary.sod.signerInfo.signature.toNumberArray(),
    })
  })

  it("should get the right country code from DSC", () => {
    const result = getDSCCountry(PASSPORTS.mary.sod.certificate)
    expect(result).toBe("ZKR")
  })

  it("should get the right integrity check circuit inputs", async () => {
    const result = await getIntegrityCheckCircuitInputs(PASSPORTS.mary, SALT, SALT)
    expect(result).toEqual({
      current_date: format(new Date(), "yyyyMMdd"),
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      signed_attributes: rightPadArrayWithZeros(
        PASSPORTS.mary.sod.signerInfo.signedAttrs.bytes.toNumberArray(),
        200,
      ),
      signed_attributes_size: 104,
      e_content: rightPadArrayWithZeros(
        PASSPORTS.mary.sod.encapContentInfo.eContent.bytes.toNumberArray(),
        700,
      ),
      e_content_size: 98,
      dg1_offset_in_e_content: 27,
      comm_in: "0x11557e9744e81d78af2760ee744c96789fe3aca92e3ea6dcf0a2d4b30bfc5a6d",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      salt_in: EXPECTED_SALT,
      salt_out: EXPECTED_SALT,
    })
  })

  it("should get the correct first name range", () => {
    const result = getFirstNameRange(PASSPORTS.mary)
    expect(result).toEqual([10, 16])
  })

  it("should get the correct last name range", () => {
    const result = getLastNameRange(PASSPORTS.mary)
    // There's overlap with the first name range as the angle brackets are included
    expect(result).toEqual([5, 12])
  })

  it("should get the correct full name range", () => {
    const result = getFullNameRange(PASSPORTS.mary)
    expect(result).toEqual([5, 44])
  })

  it("should get the correct disclose circuit inputs", async () => {
    const query: Query = {
      firstname: { disclose: true },
      lastname: { disclose: true },
      birthdate: { disclose: true },
      nationality: { disclose: true },
      issuing_country: { disclose: true },
    }

    const result = await getDiscloseCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      disclose_mask: [
        0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      ],
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should calculate the correct age from passport", () => {
    const result = calculateAge(PASSPORTS.mary)
    expect(result).toBe(50)
  })

  it("should get the correct age circuit inputs", async () => {
    const query: Query = {
      age: { gte: 18 },
    }
    const result = await getAgeCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      current_date: format(new Date(), "yyyyMMdd"),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
      min_age_required: 18,
      max_age_required: 0,
    })
  })

  it("should get the correct nationality inclusion circuit inputs", async () => {
    const query: Query = {
      nationality: { in: ["ZKR", "FRA", "GBR", "USA"] },
    }
    const result = await getNationalityInclusionCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      country_list: rightPadCountryCodeArray(["ZKR", "FRA", "GBR", "USA"], 200),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct nationality exclusion circuit inputs", async () => {
    const query: Query = {
      nationality: { out: ["FRA", "USA", "GBR"] },
    }
    const result = await getNationalityExclusionCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      // Notice how the country code are sorted compared to above
      country_list: rightPadCountryCodeArray(["FRA", "GBR", "USA"], 200).map((country) =>
        getCountryWeightedSum(country as Alpha3Code),
      ),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct issuing country inclusion circuit inputs", async () => {
    const query: Query = {
      issuing_country: { in: ["ZKR", "FRA", "GBR", "USA"] },
    }
    const result = await getIssuingCountryInclusionCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      country_list: rightPadCountryCodeArray(["ZKR", "FRA", "GBR", "USA"], 200),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct issuing country exclusion circuit inputs", async () => {
    const query: Query = {
      issuing_country: { out: ["FRA", "USA", "GBR"] },
    }
    const result = await getIssuingCountryExclusionCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      country_list: rightPadCountryCodeArray(["FRA", "GBR", "USA"], 200).map((country) =>
        getCountryWeightedSum(country as Alpha3Code),
      ),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
    })
  })

  it("should get the correct birthdate circuit inputs", async () => {
    const query: Query = {
      birthdate: { gte: new Date("1980-01-01"), lte: new Date("1990-01-01") },
    }
    const result = await getBirthdateCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      current_date: format(new Date(), "yyyyMMdd"),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
      min_date: "19800101",
      max_date: "19900101",
    })
  })

  it("should get the correct expiry date circuit inputs", async () => {
    const query: Query = {
      expiry_date: { gte: new Date("2025-01-01"), lte: new Date("2035-12-31") },
    }
    const result = await getExpiryDateCircuitInputs(PASSPORTS.mary, query, SALT, SERVICE_SCOPE, SERVICE_SUBSCOPE)
    expect(result).toEqual({
      dg1: rightPadArrayWithZeros(PASSPORTS.mary.dataGroups[0].value, 95),
      current_date: format(new Date(), "yyyyMMdd"),
      comm_in: "0x0aa7611a314621850d217b19928af38909443d8b6bb5f2dee6907243d6f80c16",
      private_nullifier: "0x287e4139c68b178bde9d7e2b1ef3a63df1ffe3283d80c0ae3b4f4b7b88b5a1b6",
      service_scope: EXPECTED_SERVICE_SCOPE,
      service_subscope: EXPECTED_SERVICE_SUBSCOPE,
      salt: EXPECTED_SALT,
      min_date: "20250101",
      max_date: "20351231",
    })
  })

  // TODO
  it("should get the correct sanctions circuit inputs", async () => {
    // const query: Query = {
    //   sanctions: true,
    // }
    // const result = await getSanctionsCircuitInputs(PASSPORTS.mary, query, 1n, 2n, 3n)
    // expect(result).toEqual({
  })
})
