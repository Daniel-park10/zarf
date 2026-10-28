// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zarf-dev/zarf/src/pkg/helpers"
	"github.com/zarf-dev/zarf/src/pkg/logger"
)

// SignerKeypair wraps a signature.Signer to satisfy sigstore-go's sign.Keypair interface.
type SignerKeypair struct {
	signer signature.Signer
	pubKey crypto.PublicKey
	hint   []byte
}

// NewSignerKeypair creates a SignerKeypair wrapping the provided signature.Signer.
func NewSignerKeypair(signer signature.Signer) (*SignerKeypair, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}
	pubKey, err := signer.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("retrieving public key: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	hashedBytes := sha256.Sum256(pubKeyBytes)
	hint := []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))

	return &SignerKeypair{
		signer: signer,
		pubKey: pubKey,
		hint:   hint,
	}, nil
}

// GetHashAlgorithm returns the hash algorithm used for signing.
func (k *SignerKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

// GetSigningAlgorithm returns the signature algorithm matching the public key.
func (k *SignerKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	switch pub := k.pubKey.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case elliptic.P384():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		case elliptic.P521():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
		default:
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		}
	case *rsa.PublicKey:
		return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
	case ed25519.PublicKey:
		return protocommon.PublicKeyDetails_PKIX_ED25519
	default:
		return protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
	}
}

// GetHint returns the base64-encoded SHA-256 fingerprint of the public key.
func (k *SignerKeypair) GetHint() []byte {
	return k.hint
}

// GetKeyAlgorithm returns the key algorithm family name.
func (k *SignerKeypair) GetKeyAlgorithm() string {
	switch k.pubKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey:
		return "ED25519"
	default:
		return ""
	}
}

// GetPublicKey returns the public key.
func (k *SignerKeypair) GetPublicKey() crypto.PublicKey {
	return k.pubKey
}

// GetPublicKeyPem returns the public key encoded as PEM.
func (k *SignerKeypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(k.pubKey)
	if err != nil {
		return "", err
	}
	return string(pubKeyBytes), nil
}

// SignData signs the provided data and returns the signature and digest.
func (k *SignerKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	sig, err := k.signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(data)
	return sig, digest[:], nil
}

// loadSigner resolves a signature.Signer from either a KMS reference or a local key file.
func loadSigner(ctx context.Context, keyRef string, passwordBytes []byte) (signature.Signer, error) {
	if strings.Contains(keyRef, "://") {
		kmsSigner, err := kms.Get(ctx, keyRef, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("reading key: %w", err)
		}
		return kmsSigner, nil
	}

	keyBytes, err := os.ReadFile(keyRef)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	signer, err := cosign.LoadPrivateKey(keyBytes, passwordBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	return signer, nil
}

// SignBlobWithOptions signs a blob using native sigstore-go operations and writes
// the Sigstore bundle to opts.BundlePath.
func SignBlobWithOptions(ctx context.Context, blobPath string, opts SignBlobOptions) ([]byte, error) {
	l := logger.From(ctx)
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	if opts.KeyRef != "" && opts.Key == "" {
		opts.Key = opts.KeyRef
	}

	if err := opts.CheckOverwrite(ctx); err != nil {
		return nil, err
	}

	blobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, fmt.Errorf("reading blob to sign: %w", err)
	}

	var keypair sign.Keypair
	bundleOpts := sign.BundleOptions{
		Context: ctx,
	}

	if opts.Key != "" {
		var passwordBytes []byte
		if opts.PassFunc != nil {
			pw, err := opts.PassFunc(false)
			if err != nil {
				return nil, fmt.Errorf("reading key password: %w", err)
			}
			passwordBytes = pw
		} else if opts.Password != "" {
			passwordBytes = []byte(opts.Password)
		}

		signer, err := loadSigner(ctx, opts.Key, passwordBytes)
		if err != nil {
			return nil, err
		}
		kp, err := NewSignerKeypair(signer)
		if err != nil {
			return nil, err
		}
		keypair = kp
	} else {
		// Keyless flow via EphemeralKeypair
		ephemeralKey, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
		}
		keypair = ephemeralKey

		if opts.Fulcio.URL != "" {
			fulcioOpts := &sign.FulcioOptions{
				BaseURL: opts.Fulcio.URL,
				Timeout: opts.Timeout,
			}
			fulcio := sign.NewFulcio(fulcioOpts)
			bundleOpts.CertificateProvider = fulcio
			bundleOpts.CertificateProviderOptions = &sign.CertificateProviderOptions{
				IDToken: opts.Fulcio.IdentityToken,
			}
		}
	}

	if opts.TlogUpload && opts.Rekor.URL != "" {
		rekorClient := sign.NewRekor(&sign.RekorOptions{
			BaseURL: opts.Rekor.URL,
			Timeout: opts.Timeout,
		})
		bundleOpts.TransparencyLogs = []sign.Transparency{rekorClient}
	}

	if opts.TSAServerURL != "" {
		tsa := sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
			URL:     opts.TSAServerURL,
			Timeout: opts.Timeout,
		})
		bundleOpts.TimestampAuthorities = []*sign.TimestampAuthority{tsa}
	}

	content := &sign.PlainData{Data: blobBytes}
	pbBundle, err := sign.Bundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("signing with sigstore-go: %w", err)
	}

	// Validate bundle structure
	if _, err := bundle.NewBundle(pbBundle); err != nil {
		return nil, fmt.Errorf("validating created bundle: %w", err)
	}

	bundleJSON, err := protojson.MarshalOptions{Indent: "  "}.Marshal(pbBundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle to json: %w", err)
	}

	if opts.BundlePath != "" {
		if err := os.WriteFile(opts.BundlePath, bundleJSON, helpers.ReadWriteUser); err != nil {
			return nil, fmt.Errorf("writing bundle: %w", err)
		}
		l.Debug("wrote sigstore-go bundle", "path", opts.BundlePath)
	}

	var sigBytes []byte
	if sig := pbBundle.GetMessageSignature(); sig != nil {
		sigBytes = sig.GetSignature()
	}

	if opts.OutputSignature != "" {
		outBytes := sigBytes
		if opts.Base64Output {
			outBytes = []byte(base64.StdEncoding.EncodeToString(sigBytes))
		}
		if err := os.WriteFile(opts.OutputSignature, outBytes, helpers.ReadWriteUser); err != nil {
			return nil, fmt.Errorf("writing signature file: %w", err)
		}
		l.Debug("wrote signature file", "path", opts.OutputSignature)
	}

	return sigBytes, nil
}
