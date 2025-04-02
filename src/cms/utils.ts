import { ECParameters } from "@peculiar/asn1-ecc"
import { p256 } from "@noble/curves/p256"
import { p384 } from "@noble/curves/p384"
import { p521 } from "@noble/curves/p521"
import { BRAINPOOL_CURVES, CURVE_OIDS } from "./constants"

export function getCurveName(ecParams: ECParameters): string {
  if (ecParams.namedCurve) {
    return CURVE_OIDS[ecParams.namedCurve as keyof typeof CURVE_OIDS] ?? ""
  }
  if (!ecParams.specifiedCurve) {
    return ""
  }
  const a = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.a).toString("hex")}`)
  const b = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.curve.b).toString("hex")}`)
  const n = BigInt(`0x${Buffer.from(ecParams.specifiedCurve.order).toString("hex")}`)
  const p = BigInt(
    `0x${Buffer.from(ecParams.specifiedCurve.fieldID.parameters.slice(2)).toString("hex")}`,
  )

  if (a == p256.CURVE.a && b == p256.CURVE.b && n == p256.CURVE.n && p == p256.CURVE.Fp.ORDER) {
    return "P-256"
  } else if (
    a == p384.CURVE.a &&
    b == p384.CURVE.b &&
    n == p384.CURVE.n &&
    p == p384.CURVE.Fp.ORDER
  ) {
    return "P-384"
  } else if (
    a == p521.CURVE.a &&
    b == p521.CURVE.b &&
    n == p521.CURVE.n &&
    p == p521.CURVE.Fp.ORDER
  ) {
    return "P-521"
  }

  for (const key in BRAINPOOL_CURVES) {
    if (
      a == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].a &&
      b == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].b &&
      n == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].n &&
      p == BRAINPOOL_CURVES[key as keyof typeof BRAINPOOL_CURVES].p
    ) {
      return key
    }
  }

  return `unknown curve`
}
