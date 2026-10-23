package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ActivateCredential recovers the secret the control plane encrypted to
// the EK for the AK's name. The TPM releases it only if the AK is loaded in
// the same TPM as the EK and its name matches the one the control plane
// used, which proves the AK is resident in the endorsed TPM.
func ActivateCredential(t transport.TPM, ek, ak *Key, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	// The TCG EK templates use PolicySecret(TPM_RH_ENDORSEMENT).
	ekAuth := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(t transport.TPM, s tpm2.TPMISHPolicy, nonce tpm2.TPM2BNonce) error {
		_, err := tpm2.PolicySecret{
			AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
			PolicySession: s,
			NonceTPM:      nonce,
		}.Execute(t)
		return err
	})
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.Handle, Name: ek.Name, Auth: ekAuth},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encryptedSecret},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm: activate credential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}
