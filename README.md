# NebulAuth JavaScript SDK

JavaScript SDK for NebulAuth runtime API with TypeScript type support.

## Install (local)

```bash
cd "NebulAuth SDKs/Javascript/Typescript"
npm install
npm run build
```

Then consume locally in another project with:

```bash
npm install /absolute/path/to/NebulAuth\ SDKs/Javascript/Typescript
```

## JavaScript usage

```js
import { NebulAuthClient } from 'nebulauth-sdk-js'

const client = new NebulAuthClient({
  // baseUrl defaults to https://api.nebulauth.com/api/v1
  // baseUrl: 'https://api.nebulauth.com/api/v1',
  bearerToken: 'mk_at_...',
  signingSecret: 'mk_sig_...',
  serviceSlug: 'your-service',
  replayProtection: 'strict', // 'none' | 'nonce' | 'strict'
})

const verify = await client.verifyKey({
  key: 'mk_live_...',
  requestId: 'req-123',
  hwid: 'WIN-DEVICE-12345',
})

const redeem = await client.redeemKey({
  key: 'mk_live_...',
  discordId: '123456789012345678',
})

const reset = await client.resetHwid({
  discordId: '123456789012345678',
  key: 'mk_live_...',
})
```

## TypeScript usage

```ts
import { NebulAuthClient, type VerifyKeyInput } from 'nebulauth-sdk-js'

const client = new NebulAuthClient({
  // baseUrl: 'https://api.nebulauth.com/api/v1',
  bearerToken: 'mk_at_...',
  signingSecret: 'mk_sig_...',
  serviceSlug: 'your-service',
})

const payload: VerifyKeyInput = {
  key: 'mk_live_...',
  requestId: 'req-123',
}

const result = await client.verifyKey(payload)
console.log(result.statusCode, result.data)
```

## PoP flow

```js
const bootstrap = await client.authVerify({ key: 'mk_live_...', hwid: 'WIN-DEVICE-12345' })

if (bootstrap.data?.valid) {
  const verifyPop = await client.verifyKey({
    key: 'mk_live_...',
    usePop: true,
    accessToken: bootstrap.data.accessToken,
    popKey: bootstrap.data.popKey,
  })
}
```

## Notes

- Canonical signing string:
  - `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256`
- Canonical path strips base URL path prefix (e.g. `/api/v1`) before signing.
- NebulAuth may return HTTP 200 with logical denials like `{ "valid": false, "reason": "NOT_FOUND" }`.
- Build output is generated to `dist/` as both ESM (`index.js`) and CommonJS (`index.cjs`) with TypeScript declarations (`index.d.ts`).

## Tests

- Unit/contract tests (mocked HTTP):

```bash
npm test
```

- Live integration tests (real API calls, optional):

```bash
NEBULAUTH_LIVE_TEST=1 \
NEBULAUTH_BEARER_TOKEN=mk_at_... \
NEBULAUTH_SIGNING_SECRET=mk_sig_... \
NEBULAUTH_TEST_KEY=mk_live_... \
npm run test:live
```

Optional: `NEBULAUTH_BASE_URL=...`, `NEBULAUTH_TEST_HWID=...`
