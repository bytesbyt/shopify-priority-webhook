import crypto from "crypto";

function verifyShopifyWebhook(rawBody, signature, secret) {
  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("base64");

  console.log("Signature exists:", !!signature);
  console.log("Signature length:", signature ? signature.length : 0);
  console.log("Calculated digest:", digest);
  console.log("Digest matches:", signature === digest);

  return !!signature && digest === signature;
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const rawBody = await readRawBody(req);
    const signature = req.headers["x-shopify-hmac-sha256"];
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET;

    console.log("Secret exists:", !!secret);
    console.log("Raw body length:", rawBody.length);
    console.log("Raw body first 200 chars:", rawBody.slice(0, 200));

    if (!secret) {
      return res.status(500).json({ error: "Missing SHOPIFY_WEBHOOK_SECRET" });
    }

    if (!verifyShopifyWebhook(rawBody, signature, secret)) {
      return res.status(401).json({ error: "Invalid webhook signature" });
    }

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error("Webhook error:", error.message);
    return res.status(500).json({ error: error.message });
  }
}