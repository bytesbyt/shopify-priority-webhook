import crypto from "crypto";
import axios from "axios";

function verifyShopifyWebhook(rawBody, signature, secret) {
  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("base64");

  if (!signature) return false;

  const digestBuffer = Buffer.from(digest, "utf8");
  const signatureBuffer = Buffer.from(signature, "utf8");

  if (digestBuffer.length !== signatureBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(digestBuffer, signatureBuffer);
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
    const priorityUrl = process.env.PRIORITY_URL;
    const priorityUser = process.env.PRIORITY_USER;
    const priorityPass = process.env.PRIORITY_PASS;

    if (!secret) {
      return res.status(500).json({ error: "Missing SHOPIFY_WEBHOOK_SECRET" });
    }
    if (!priorityUrl) {
      return res.status(500).json({ error: "Missing PRIORITY_URL" });
    }

    if (!verifyShopifyWebhook(rawBody, signature, secret)) {
      return res.status(401).json({ error: "Invalid webhook signature" });
    }

    let order;
    try {
      order = JSON.parse(rawBody);
    } catch {
      return res.status(400).json({ error: "Invalid JSON body" });
    }

    const axiosConfig = {
      headers: { "Content-Type": "application/json" },
      timeout: 10000
    };

    if (priorityUser && priorityPass) {
      axiosConfig.auth = {
        username: priorityUser,
        password: priorityPass
      };
    }

    const response = await axios.post(priorityUrl, order, axiosConfig);
    console.log("Forwarded Shopify order", {
      shopifyOrderId: order?.id ?? null,
      priorityStatus: response.status
    });

    return res.status(200).json({
      ok: true,
      forwarded: true,
      priorityStatus: response.status
    });
  } catch (error) {
    console.error("Webhook forward error:", {
      message: error?.message,
      status: error?.response?.status ?? null
    });
    return res.status(500).json({
      error: "Failed to process webhook",
      details: error?.response?.data || error?.message
    });
  }
}