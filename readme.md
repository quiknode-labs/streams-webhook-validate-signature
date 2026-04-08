# Compressed Streams webhook validation (Node.js)

Small **Express** server that verifies **Quicknode Streams** webhook **HMAC-SHA256** signatures and supports **gzip-compressed** bodies (`Content-Encoding: gzip`), matching [How to Validate Incoming Streams Webhook Messages](https://www.quicknode.com/guides/quicknode-products/streams/validating-incoming-streams-webhook-messages).

Signature input is: `nonce + timestamp + payload` (UTF-8 string), keyed by your Stream **security token**.

## Gzip and decompression

Quicknode Streams signs the **uncompressed JSON** body (the same bytes that are gzipped for transport when compression is enabled). Your verifier must run HMAC on that **decoded UTF-8 string**, not on the raw gzip octets.

This app uses **`express.raw()`**, which is implemented with **[`body-parser`](https://github.com/expressjs/body-parser)**. When the request has **`Content-Encoding: gzip`**, body-parser **decompresses the body by default** before the bytes are stored in **`req.body`**. So **`req.body`** is already the **JSON bytes**; the code uses **`req.body.toString("utf8")`** as the payload for verification.

Important details:

- The **`Content-Encoding: gzip`** header is **not** stripped. It can still be present even though **`req.body`** holds decoded JSON—**do not** call `zlib.gunzip` on **`req.body`** in that case or you will get errors such as zlib’s “incorrect header check.”

## Setup

1. Copy `.env.example` to `.env` and set `QN_STREAM_SECRET` to the security token from your Stream’s **Settings** in the [Quicknode dashboard](https://dashboard.quicknode.com/streams).

2. Install and run (default port **9999**):

```bash
npm install
npm start
```

Optional: `PORT=3000 npm start`

3. Expose with [ngrok](https://ngrok.com/) and set the Stream webhook URL to `https://<your-tunnel>/webhook`.

```bash
ngrok http 9999
```

## Security notes

- Do not commit `.env` or embed the token in source code for real deployments.
- Consider timestamp skew checks to reduce replay risk (see the guide’s best practices).
