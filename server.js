/**
 * Quicknode Streams webhook verifier (Node.js).
 * Verifies HMAC-SHA256 over nonce + timestamp + payload (after gzip decode if needed).
 * @see https://www.quicknode.com/guides/quicknode-products/streams/validating-incoming-streams-webhook-messages
 */

require("dotenv").config();
const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT) || 9999;
const SECRET_KEY = process.env.QN_STREAM_SECRET;

function verifySignature(secretKey, payload, nonce, timestamp, givenSignature) {
  const signatureData = nonce + timestamp + payload;
  const signatureBytes = Buffer.from(signatureData, "utf8");
  const hmac = crypto.createHmac("sha256", Buffer.from(secretKey, "utf8"));
  hmac.update(signatureBytes);
  const computedSignature = hmac.digest("hex");

  console.log("\nSignature debug:");
  console.log("Message components:");
  console.log("- Nonce:", nonce);
  console.log("- Timestamp:", timestamp);
  console.log("- Payload preview:", payload.slice(0, 100));
  console.log("\nSignatures:");
  console.log("- Computed:", computedSignature);
  console.log("- Given:", givenSignature);

  return crypto.timingSafeEqual(
    Buffer.from(computedSignature, "hex"),
    Buffer.from(givenSignature, "hex"),
  );
}

app.post(
  "/webhook",
  express.raw({ type: () => true, limit: "50mb" }),
  (req, res) => {
    if (!SECRET_KEY || SECRET_KEY === "your_security_token_here") {
      console.error("Set QN_STREAM_SECRET in .env (see .env.example)");
      return res.status(500).send("Server misconfigured: missing secret");
    }

    const nonce = req.headers["x-qn-nonce"];
    const timestamp = req.headers["x-qn-timestamp"];
    const givenSignature = req.headers["x-qn-signature"];

    if (!nonce || !timestamp || !givenSignature) {
      console.error("Missing required headers");
      return res.status(400).send("Missing required headers");
    }

    let payloadString = req.body.toString("utf8");

    try {
      const isValid = verifySignature(
        SECRET_KEY,
        payloadString,
        nonce,
        timestamp,
        givenSignature,
      );

      if (isValid) {
        console.log("\n✅ Signature verified successfully");
        return res.status(200).send("Webhook received and verified");
      }
      console.log("\n❌ Signature verification failed");
      return res.status(401).send("Invalid signature");
    } catch (error) {
      console.error("Error processing webhook:", error);
      return res.status(500).send("Error processing webhook");
    }
  },
);

app.listen(PORT, () => {
  console.log(
    `Streams webhook verifier listening on http://localhost:${PORT}/webhook`,
  );
});
