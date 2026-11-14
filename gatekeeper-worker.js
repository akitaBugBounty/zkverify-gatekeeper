// zkVerify Agent Games — Proof Gatekeeper agent (Cloudflare Worker).
// Receives a signed JSON task, returns a deterministic approve/reject
// decision after checking every field against the 7 documented trap types.
// Signs every response with the platform HMAC secret (env AGENT_GAMES_SECRET).
// Fail closed: any uncertainty or timeout -> REJECT.

const seenProofs = new Set();

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return hex(sig);
}

function normAddr(a) { return String(a || "").toLowerCase(); }

function decide(input) {
  const t = input || {};
  const proofTx = t.proof_tx || "";
  // 1. Verification key substitution
  if (t.proof_vk && t.registered_vk && normAddr(t.proof_vk) !== normAddr(t.registered_vk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", proof_tx: proofTx };
  }
  // 2. Threshold mismatch (public balance below minimum)
  try {
    if (t.public_balance !== undefined && t.minimum !== undefined) {
      if (BigInt(t.public_balance) < BigInt(t.minimum)) {
        return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", proof_tx: proofTx };
      }
    }
  } catch (_) { return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", proof_tx: proofTx }; }
  // 3. Proof reused
  if (proofTx) {
    if (seenProofs.has(proofTx)) {
      return { decision: "REJECT", reason_code: "PROOF_REUSED", proof_tx: proofTx };
    }
    seenProofs.add(proofTx);
  }
  // 4. Expired condition
  if (t.expiry_block !== undefined && t.current_block !== undefined) {
    if (Number(t.current_block) >= Number(t.expiry_block)) {
      return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", proof_tx: proofTx };
    }
  }
  // 5. Recipient mismatch
  if (t.recipient && t.condition_recipient && normAddr(t.recipient) !== normAddr(t.condition_recipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", proof_tx: proofTx };
  }
  // 6. Amount overflow
  try {
    if (t.amount !== undefined && t.max_transfer !== undefined) {
      if (BigInt(t.amount) > BigInt(t.max_transfer)) {
        return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", proof_tx: proofTx };
      }
    }
  } catch (_) { return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", proof_tx: proofTx }; }
  // 7. Valid condition
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", proof_tx: proofTx };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const secret = env.AGENT_GAMES_SECRET || "";
    // Health check. The platform's signed preflight probe expects the
    // endpoint to answer a protocol-v1 handshake: exactly
    // { ok: true, protocolVersion: "v1" }, signed with the HMAC secret.
    // (An earlier shape {"ok":true,"agent":"gatekeeper","version":"1"}
    // was rejected with "The endpoint must return signed protocol-v1 JSON.")
    if (request.method === "GET") {
      const body = JSON.stringify({ ok: true, protocolVersion: "v1" });
      const headers = { "content-type": "application/json" };
      if (secret) {
        headers["x-agent-games-signature"] = "sha256=" + (await hmacSha256(secret, body));
      }
      return new Response(body, { status: 200, headers });
    }
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    const raw = await request.text();
    // Verify HMAC on the raw body (accept "sha256=<hex>" or raw hex).
    if (secret) {
      const sig = request.headers.get("x-agent-games-signature") || "";
      const expect = await hmacSha256(secret, raw);
      const given = sig.startsWith("sha256=") ? sig.slice(7) : sig;
      if (given.toLowerCase() !== expect.toLowerCase()) {
        return new Response(JSON.stringify({ error: "bad_signature" }), {
          status: 401, headers: { "content-type": "application/json" },
        });
      }
    }
    let task;
    try { task = JSON.parse(raw); } catch (_) {
      return new Response(JSON.stringify({ error: "bad_json" }), {
        status: 400, headers: { "content-type": "application/json" },
      });
    }
    // Protocol handshake: the platform's signed preflight probe sends
    // {"type":"agent-games.preflight.v1", ...} and expects exactly
    // { ok: true, protocolVersion: "v1" }, signed. Anything else is
    // rejected with "The endpoint must return signed protocol-v1 JSON."
    if (typeof task.type === "string" && task.type.startsWith("agent-games.preflight")) {
      const preBody = JSON.stringify({ ok: true, protocolVersion: "v1" });
      const preHeaders = { "content-type": "application/json" };
      if (secret) {
        preHeaders["x-agent-games-signature"] = "sha256=" + (await hmacSha256(secret, preBody));
      }
      return new Response(preBody, { status: 200, headers: preHeaders });
    }
    const result = decide(task.input || {});
    const body = JSON.stringify(result);
    const headers = { "content-type": "application/json" };
    if (secret) {
      headers["x-agent-games-signature"] = "sha256=" + (await hmacSha256(secret, body));
    }
    return new Response(body, { status: 200, headers });
  },
};
