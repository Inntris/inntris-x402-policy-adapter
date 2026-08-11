/** Compatibility type required by @kya-os/mcp@1.12.0 declarations when the
 * repository deliberately compiles without the browser DOM library. */
interface CryptoKey {
  readonly type: "secret" | "public" | "private";
}

interface Crypto {}
