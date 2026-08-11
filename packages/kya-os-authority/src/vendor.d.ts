declare module "@digitalbazaar/eddsa-jcs-2022-cryptosuite" {
  interface Cryptosuite {
    name: string;
    canonize(input: unknown): Promise<string>;
    createVerifyData(input: {
      cryptosuite: Cryptosuite;
      document: Record<string, unknown>;
      proof: Record<string, unknown>;
    }): Promise<Uint8Array>;
    createVerifier(input: {
      verificationMethod: Record<string, unknown>;
    }): Promise<{ verify(input: { data: Uint8Array; signature: Uint8Array }): Promise<boolean> }>;
  }

  export function createSignCryptosuite(): Cryptosuite;
  export function createVerifyCryptosuite(): Cryptosuite;
}

declare module "base58-universal" {
  export function decode(value: string): Uint8Array;
  export function encode(value: Uint8Array): string;
}
