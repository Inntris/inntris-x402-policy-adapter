declare module "@digitalbazaar/eddsa-jcs-2022-cryptosuite" {
  interface Cryptosuite {
    name: string;
    canonize(input: unknown): Promise<string>;
    createVerifyData(input: {
      cryptosuite: Cryptosuite;
      document: Record<string, unknown>;
      proof: Record<string, unknown>;
    }): Promise<Uint8Array>;
  }

  export function createSignCryptosuite(): Cryptosuite;
}

declare module "base58-universal" {
  export function encode(value: Uint8Array): string;
}
