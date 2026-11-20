package agent

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"

	attestv1 "github.com/0xciph3r/attest/api/gen/attest/v1"
	"github.com/0xciph3r/attest/internal/tpm"
)

// TPM is the node's TPM as the agent uses it.
type TPM interface {
	// AKPublic is the TPMT_PUBLIC of the attestation key.
	AKPublic() []byte
	// ActivateCredential recovers an enrollment secret encrypted to the EK
	// for the AK.
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)
	// Evidence quotes pcrs and certifies the node key, both over the key
	// binding of nonce and the node key, and adds the event log.
	Evidence(nonce []byte, pcrs []uint32) (*attestv1.Evidence, error)
	// NodeKey signs with the TPM-resident node identity key.
	NodeKey() crypto.Signer
}

// Device is a TPM reached through a transport: /dev/tpmrm0 on a node, or
// swtpm in development.
type Device struct {
	t            transport.TPM
	ek, ak, node *tpm.Key
	signer       *tpm.Signer
	eventLog     string
}

// DeviceConfig selects the keys and event log a Device uses.
type DeviceConfig struct {
	EKType tpm.EKType
	// NodeKeyUnique selects the node key; see tpm.NodeKeyTemplate.
	NodeKeyUnique []byte
	// EventLogPath is the measured-boot log; default tpm.DefaultEventLogPath.
	EventLogPath string
}

// OpenDevice derives the EK, AK and node key in t. Close flushes them.
func OpenDevice(t transport.TPM, cfg DeviceConfig) (*Device, error) {
	if cfg.EventLogPath == "" {
		cfg.EventLogPath = tpm.DefaultEventLogPath
	}
	d := &Device{t: tpm.Locked(t), eventLog: cfg.EventLogPath}
	var err error
	if d.ek, err = tpm.LoadEK(d.t, cfg.EKType); err != nil {
		return nil, err
	}
	if d.ak, err = tpm.LoadAK(d.t); err != nil {
		d.Close()
		return nil, err
	}
	if d.node, err = tpm.LoadNodeKey(d.t, cfg.NodeKeyUnique); err != nil {
		d.Close()
		return nil, err
	}
	if d.signer, err = tpm.NewSigner(d.t, d.node); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// Close flushes the device's keys. The transport stays open.
func (d *Device) Close() {
	for _, k := range []*tpm.Key{d.node, d.ak, d.ek} {
		if k != nil {
			_ = k.Flush(d.t)
		}
	}
	d.ek, d.ak, d.node = nil, nil, nil
}

// AKPublic implements TPM.
func (d *Device) AKPublic() []byte { return d.ak.PublicBytes() }

// ActivateCredential implements TPM.
func (d *Device) ActivateCredential(blob, secret []byte) ([]byte, error) {
	return tpm.ActivateCredential(d.t, d.ek, d.ak, blob, secret)
}

// NodeKey implements TPM.
func (d *Device) NodeKey() crypto.Signer { return d.signer }

// Evidence implements TPM.
func (d *Device) Evidence(nonce []byte, pcrs []uint32) (*attestv1.Evidence, error) {
	if len(nonce) == 0 {
		return nil, errors.New("agent: empty nonce")
	}
	q := tpm.KeyBindingData(nonce, d.node.Name.Buffer)
	cert, err := tpm.Certify(d.t, d.ak, d.node, q)
	if err != nil {
		return nil, err
	}
	quote, err := tpm.MakeQuote(d.t, d.ak, q, pcrs)
	if err != nil {
		return nil, err
	}
	log, err := tpm.ReadEventLog(d.eventLog)
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	return &attestv1.Evidence{
		Attest: quote.Attest, Signature: quote.Signature, Pcrs: quote.PCRs, EventLog: log,
		NodeKey: &attestv1.NodeKeyEvidence{Public: d.node.PublicBytes(), Certify: cert.Attest, CertifySignature: cert.Signature},
	}, nil
}
