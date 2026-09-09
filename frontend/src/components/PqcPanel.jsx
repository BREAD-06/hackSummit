import React from "react";

import { Card, bytes } from "./ui.jsx";

/**
 * Post-quantum transport posture.
 *
 * Not a chart — there is no quantity here worth plotting. What matters is that the
 * named primitives, their standards, and the key fingerprints are legible, because
 * "we use PQC" is unverifiable and "ML-KEM-512 / FIPS 203, server key fp 3f9a…" is
 * something an operator can actually check against the endpoint's own config.
 */
function Spec({ title, sub, rows }) {
  return (
    <div className="spec">
      <h3>{title}</h3>
      {sub && <p className="spec-sub">{sub}</p>}
      <dl>
        {rows.map(([k, v]) => (
          <React.Fragment key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </React.Fragment>
        ))}
      </dl>
    </div>
  );
}

export default function PqcPanel({ pqc }) {
  if (!pqc) {
    return (
      <Card title="Secure transmission">
        <p className="empty-state">Loading crypto posture…</p>
      </Card>
    );
  }

  const { kem, signature: sg, aead, protocol } = pqc;

  return (
    <Card
      title="Secure transmission (post-quantum)"
      hint={`${pqc.sessions_active} live session${pqc.sessions_active === 1 ? "" : "s"}`}
      className="detail"
    >
      <div className="specs">
        <Spec
          title="Key encapsulation"
          sub={`${kem.algorithm} · ${kem.standard}`}
          rows={[
            ["Public key", bytes(kem.public_key_bytes)],
            ["Ciphertext", bytes(kem.ciphertext_bytes)],
            ["Shared secret", bytes(kem.shared_secret_bytes)],
            ["Classical equiv.", `${kem.classical_equivalent_bits}-bit`],
            ["Server key fp", <span className="mono">{kem.fingerprint}</span>],
          ]}
        />
        <Spec
          title="Signature"
          sub={`${sg.algorithm} · ${sg.standard}`}
          rows={[
            ["Public key", bytes(sg.public_key_bytes)],
            ["Signature", bytes(sg.signature_bytes)],
            ["Classical equiv.", `${sg.classical_equivalent_bits}-bit`],
            ["Server key fp", <span className="mono">{sg.fingerprint}</span>],
          ]}
        />
        <Spec
          title="Payload encryption"
          sub={`${aead.algorithm} · ${aead.kdf}`}
          rows={[
            ["Session key", `${aead.key_bytes * 8}-bit`],
            ["Nonce", bytes(aead.nonce_bytes)],
            ["Order", protocol.order],
            ["Replay defence", protocol.replay_protection],
            ["Keys at rest", protocol.session_keys_persisted ? "persisted" : "never persisted"],
          ]}
        />
      </div>
      <p className="footnote" style={{ textAlign: "left", marginTop: 14 }}>
        Enrollment: {protocol.enrollment}. Batches are encrypted and signed before they leave the
        endpoint, so the payload is protected independently of the transport.
      </p>
    </Card>
  );
}
