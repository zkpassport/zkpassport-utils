/**
 * Certificate digest algorithm
 */
export type DigestAlgorithm = "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512"

/**
 * Certificate signature algorithm
 */
export type SignatureAlgorithm =
  | "sha1-with-rsa-signature"
  | "sha256WithRSAEncryption"
  | "sha384WithRSAEncryption"
  | "sha512WithRSAEncryption"
  | "rsassa-pss"
  | "ecdsa-with-SHA1"
  | "ecdsa-with-SHA256"
  | "ecdsa-with-SHA384"
  | "ecdsa-with-SHA512"

/**
 * Key type
 */
export enum KeyType {
  RSA = "RSA",
  EC = "ECC",
}

/**
 * RSA signature scheme
 */
export enum RSAScheme {
  PKCS = "PKCS",
  PSS = "PSS",
}

/**
 * ECDSA public key
 */
export interface ECDSAPublicKey {
  type: KeyType.EC
  curve: string
  public_key_x: string
  public_key_y: string
}

/**
 * RSA public key
 */
export interface RSAPublicKey {
  type: KeyType.RSA
  modulus: string
  exponent: number
  scheme: RSAScheme
  hash_algorithm?: DigestAlgorithm
}
