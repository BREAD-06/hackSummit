import React from "react";
import {
  Lock,
  KeyRound,
  ShieldCheck,
  Cpu,
  Layers,
  ArrowRight,
  Fingerprint,
  FileCheck,
  RefreshCw,
} from "lucide-react";
import { Card, Chip, bytes } from "../ui.jsx";

export default function SecurityView({ pqc }) {
  if (!pqc) {
    return (
      <div className="page-content">
        <p className="dim" style={{ padding: "40px 0", textAlign: "center" }}>
          Loading post-quantum cryptographic posture...
        </p>
      </div>
    );
  }

  const { kem, signature: sg, aead, protocol } = pqc;

  return (
    <div className="page-content">
      {/* Header */}
      <div>
        <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
          Post-Quantum Security & Cryptographic Posture
        </h1>
        <p className="dim" style={{ fontSize: "13px", marginTop: "2px" }}>
          Next-generation NIST FIPS-standardized lattice-based cryptography securing all endpoint-to-SOC telemetry.
        </p>
      </div>

      {/* Visual Cryptographic Pipeline Flow */}
      <Card
        title="Zero-Trust Post-Quantum Telemetry Pipeline"
        hint="Cryptographic defense against Harvest Now, Decrypt Later (HNDL) attacks"
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "14px",
            margin: "12px 0",
          }}
        >
          {/* Step 1 */}
          <div
            style={{
              padding: "16px",
              borderRadius: "var(--radius-md)",
              background: "rgba(255,255,255,0.03)",
              border: "1px solid var(--border-subtle)",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <KeyRound size={16} color="#ffffff" />
              <strong style={{ fontSize: "13px", color: "#ffffff" }}>1. Key Establishment</strong>
            </div>
            <div className="mono" style={{ fontSize: "11px", color: "var(--muted)" }}>
              {kem.algorithm} ({kem.standard})
            </div>
            <p className="dim" style={{ fontSize: "11.5px", lineHeight: "1.4" }}>
              Lattice-based module learning with errors (ML-KEM-512) establishes high-entropy ephemeral session keys.
            </p>
          </div>

          {/* Step 2 */}
          <div
            style={{
              padding: "16px",
              borderRadius: "var(--radius-md)",
              background: "rgba(255,255,255,0.03)",
              border: "1px solid var(--border-subtle)",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <FileCheck size={16} color="#ffffff" />
              <strong style={{ fontSize: "13px", color: "#ffffff" }}>2. Authentication</strong>
            </div>
            <div className="mono" style={{ fontSize: "11px", color: "var(--muted)" }}>
              {sg.algorithm} ({sg.standard})
            </div>
            <p className="dim" style={{ fontSize: "11.5px", lineHeight: "1.4" }}>
              Module lattice digital signature algorithm (ML-DSA-44) authenticates endpoint batches with cryptographic non-repudiation.
            </p>
          </div>

          {/* Step 3 */}
          <div
            style={{
              padding: "16px",
              borderRadius: "var(--radius-md)",
              background: "rgba(255,255,255,0.03)",
              border: "1px solid var(--border-subtle)",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Lock size={16} color="#ffffff" />
              <strong style={{ fontSize: "13px", color: "#ffffff" }}>3. Payload Encryption</strong>
            </div>
            <div className="mono" style={{ fontSize: "11px", color: "var(--muted)" }}>
              {aead.algorithm} · {aead.kdf}
            </div>
            <p className="dim" style={{ fontSize: "11.5px", lineHeight: "1.4" }}>
              256-bit Galois/Counter Mode AEAD encrypts telemetry batches before transmission over the public wire.
            </p>
          </div>

          {/* Step 4 */}
          <div
            style={{
              padding: "16px",
              borderRadius: "var(--radius-md)",
              background: "rgba(255,255,255,0.03)",
              border: "1px solid var(--border-subtle)",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <ShieldCheck size={16} color="#ffffff" />
              <strong style={{ fontSize: "13px", color: "#ffffff" }}>4. Replay Defense</strong>
            </div>
            <div className="mono" style={{ fontSize: "11px", color: "var(--muted)" }}>
              Strict Monotonic Sequences
            </div>
            <p className="dim" style={{ fontSize: "11.5px", lineHeight: "1.4" }}>
              Ordered sequence validation and nonce enforcement reject any replayed or out-of-order frames instantly.
            </p>
          </div>
        </div>
      </Card>

      {/* Deep Cryptographic Parameter Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: "20px" }}>
        {/* ML-KEM-512 Details */}
        <Card
          title="Key Encapsulation (ML-KEM)"
          hint={`${kem.algorithm} · ${kem.standard}`}
          icon={<KeyRound size={16} />}
        >
          <table style={{ background: "transparent" }}>
            <tbody>
              <tr>
                <td className="dim">Standard</td>
                <td className="mono">{kem.standard}</td>
              </tr>
              <tr>
                <td className="dim">Public Key Size</td>
                <td className="mono">{bytes(kem.public_key_bytes)}</td>
              </tr>
              <tr>
                <td className="dim">Ciphertext Size</td>
                <td className="mono">{bytes(kem.ciphertext_bytes)}</td>
              </tr>
              <tr>
                <td className="dim">Shared Secret</td>
                <td className="mono">{bytes(kem.shared_secret_bytes)}</td>
              </tr>
              <tr>
                <td className="dim">Classical Security Equivalence</td>
                <td className="mono" style={{ color: "#ffffff", fontWeight: 600 }}>
                  {kem.classical_equivalent_bits}-bit AES
                </td>
              </tr>
              <tr>
                <td className="dim">Server Key Fingerprint</td>
                <td className="mono dim truncate-sm" title={kem.fingerprint}>
                  {kem.fingerprint}
                </td>
              </tr>
            </tbody>
          </table>
        </Card>

        {/* ML-DSA-44 Details */}
        <Card
          title="Digital Signatures (ML-DSA)"
          hint={`${sg.algorithm} · ${sg.standard}`}
          icon={<FileCheck size={16} />}
        >
          <table style={{ background: "transparent" }}>
            <tbody>
              <tr>
                <td className="dim">Standard</td>
                <td className="mono">{sg.standard}</td>
              </tr>
              <tr>
                <td className="dim">Public Key Size</td>
                <td className="mono">{bytes(sg.public_key_bytes)}</td>
              </tr>
              <tr>
                <td className="dim">Signature Length</td>
                <td className="mono">{bytes(sg.signature_bytes)}</td>
              </tr>
              <tr>
                <td className="dim">Classical Security Equivalence</td>
                <td className="mono" style={{ color: "#ffffff", fontWeight: 600 }}>
                  {sg.classical_equivalent_bits}-bit
                </td>
              </tr>
              <tr>
                <td className="dim">Signature Verification</td>
                <td className="mono">Hardware Constant-Time</td>
              </tr>
              <tr>
                <td className="dim">Server Identity Fingerprint</td>
                <td className="mono dim truncate-sm" title={sg.fingerprint}>
                  {sg.fingerprint}
                </td>
              </tr>
            </tbody>
          </table>
        </Card>

        {/* Transport Protocol Details */}
        <Card
          title="Payload Protocol Configuration"
          hint={`${aead.algorithm} authenticated encryption`}
          icon={<Lock size={16} />}
        >
          <table style={{ background: "transparent" }}>
            <tbody>
              <tr>
                <td className="dim">Symmetric Cipher</td>
                <td className="mono">{aead.algorithm} ({aead.key_bytes * 8}-bit)</td>
              </tr>
              <tr>
                <td className="dim">Key Derivation Function</td>
                <td className="mono">{aead.kdf}</td>
              </tr>
              <tr>
                <td className="dim">IV / Nonce Size</td>
                <td className="mono">{bytes(aead.nonce_bytes)}</td>
              </tr>
              <tr>
                <td className="dim">Sequence Validation</td>
                <td className="mono">{protocol.order}</td>
              </tr>
              <tr>
                <td className="dim">Anti-Replay Mechanism</td>
                <td className="mono">{protocol.replay_protection}</td>
              </tr>
              <tr>
                <td className="dim">Keys at Rest</td>
                <td className="mono">{protocol.session_keys_persisted ? "Persisted" : "Ephemeral (In-Memory Only)"}</td>
              </tr>
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}
