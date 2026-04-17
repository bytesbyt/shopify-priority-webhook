import crypto from "crypto";
import axios from "axios";

function money(value) {
  const n = Number(value || 0);
  return n.toFixed(2);
}

function mapStatus(order) {
  if (order.cancelled_at) return "cancelled";
  if (order.fulfillment_status === "fulfilled") return "completed";
  if (order.financial_status === "paid") return "processing";
  return order.financial_status || "pending";
}

function getShippingTax(order) {
  const total = (order.shipping_lines || []).reduce((sum, line) => {
    const lineTax = (line.tax_lines || []).reduce((s, t) => s + Number(t.price || 0), 0);
    return sum + lineTax;
  }, 0);
  return money(total);
}

function getLineTax(item) {
  const total = (item.tax_lines || []).reduce((sum, t) => sum + Number(t.price || 0), 0);
  return money(total);
}

function getLineSubtotal(item) {
  const qty = Number(item.quantity || 1);
  const price = Number(item.price || 0);
  return money(qty * price);
}

function toNumberOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function buildPriorityPayload(order) {
  const billing = order.billing_address || {};
  const shipping = order.shipping_address || {};
  const shippingAmount = order.total_shipping_price_set?.shop_money?.amount || "0.00";

  const items = (order.line_items || []).map((item, index) => ({
    order_id: String(order.order_number || order.id),
    line_id: String(index + 1),
    name: item.title || null,
    partname: item.sku || item.title || null,
    quantity: String(item.quantity ?? 1),
    subtotal: getLineSubtotal(item),
    total: getLineSubtotal(item),
    subtotal_tax: getLineTax(item),
    tax_class: null,
    product_id: item.product_id || 0,
    variation_id: item.variant_id || 0,
    CoffeSizeCode: 0,
    total_tax: getLineTax(item),
    sku: item.sku || null,
    price: item.price != null ? String(item.price) : null,
    parent_name: item.title || null
  }));

  if (Number(shippingAmount) > 0) {
    items.push({
      order_id: String(order.order_number || order.id),
      line_id: String(items.length + 1),
      name: null,
      partname: "Shipment",
      quantity: "1.0",
      subtotal: money(shippingAmount),
      total: money(shippingAmount),
      subtotal_tax: getShippingTax(order),
      tax_class: null,
      product_id: 0,
      variation_id: 0,
      CoffeSizeCode: 0,
      total_tax: getShippingTax(order),
      sku: null,
      price: null,
      parent_name: null
    });
  }

  return {
    order_id: String(order.order_number || order.id),
    status: mapStatus(order),
    billing_first_name: billing.first_name || null,
    billing_last_name: billing.last_name || null,
    billing_company: billing.company || null,
    billing_address_1: billing.address1 || null,
    billing_address_2: billing.address2 || null,
    billing_city: billing.city || null,
    billing_state: billing.province || null,
    billing_postcode: billing.zip || null,
    billing_country: billing.country_code || null,
    billing_country_name: billing.country || null,
    billing_email: order.email || order.customer?.email || null,
    billing_phone: billing.phone || order.phone || null,
    shipping_first_name: shipping.first_name || null,
    shipping_last_name: shipping.last_name || null,
    shipping_company: shipping.company || null,
    shipping_address_1: shipping.address1 || null,
    shipping_address_2: shipping.address2 || null,
    shipping_city: shipping.city || null,
    shipping_state: shipping.province || null,
    shipping_postcode: shipping.zip || null,
    shipping_country: shipping.country_code || null,
    customer_note: order.note || null,
    subtotal: order.current_subtotal_price || null,
    cart_tax: money(order.current_total_tax || 0),
    shipping_tax: getShippingTax(order),
    shipping_total: money(shippingAmount),
    total: money(order.current_total_price || order.total_price || 0),
    currency: order.currency || "GBP",
    shipping_method: order.shipping_lines?.[0]?.title || null,
    payment_method: order.payment_gateway_names?.[0] || null,
    payment_method_title: order.payment_gateway_names?.join(", ") || null,
    transaction_id: order.payment_id || null,
    taxation_id: null,
    CUST: toNumberOrNull(process.env.PRIORITY_CUST),
    CUSTNAME: process.env.PRIORITY_CUSTNAME || null,
    date_created: order.created_at || null,
    parent_id: "0",
    shipping_phone: shipping.phone || null,
    created_via: "shopify",
    date_completed: null,
    date_paid: order.processed_at || null,
    cart_hash: order.cart_token || order.checkout_token || null,
    customer_id: order.customer?.id ? String(order.customer.id) : null,
    prices_include_tax: order.taxes_included ? "1" : "0",
    discount_total: money(order.current_total_discounts || 0),
    discount_tax: "0.00",
    date_modified: order.updated_at || null,
    order_key: String(order.id),
    total_tax: money(order.current_total_tax || 0),
    ZMED_WEBORDERITEMS_SUBFORM: items
  };
}

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

    const priorityPayload = buildPriorityPayload(order);

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

    const response = await axios.post(priorityUrl, priorityPayload, axiosConfig);
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