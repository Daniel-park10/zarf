// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"

	"github.com/zarf-dev/zarf/src/test/testutil"
)

func TestSigstoreSignBlobWithOptions(t *testing.T) {
	t.Parallel()

	ctx := testutil.TestContext(t)
	const keyPath = "./testdata/cosign.key"
	const pubPath = "./testdata/cosign.pub"
	const password = "test"

	payload := filepath.Join(t.TempDir(), "test-payload.txt")
	require.NoError(t, os.WriteFile(payload, []byte("sigstore-go signing test payload"), 0o600))

	t.Run("sign and verify bundle format", func(t *testing.T) {
		t.Parallel()

		bundlePath := filepath.Join(t.TempDir(), "zarf.bundle.json")
		signOpts := DefaultSignBlobOptions()
		signOpts.Key = keyPath
		signOpts.Password = password
		signOpts.BundlePath = bundlePath

		sig, err := SignBlobWithOptions(ctx, payload, signOpts)
		require.NoError(t, err)
		require.NotEmpty(t, sig)
		require.FileExists(t, bundlePath)

		info, err := ReadBundleInfo(bundlePath)
		require.NoError(t, err)
		require.Equal(t, SigningMethodKey, info.Method)

		verifyOpts := DefaultVerifyBlobOptions()
		verifyOpts.Key = pubPath
		verifyOpts.BundlePath = bundlePath
		require.NoError(t, CosignVerifyBlobWithOptions(ctx, payload, verifyOpts))
	})

	t.Run("wrong password fails", func(t *testing.T) {
		t.Parallel()

		bundlePath := filepath.Join(t.TempDir(), "zarf.bundle.json")
		signOpts := DefaultSignBlobOptions()
		signOpts.Key = keyPath
		signOpts.Password = "wrong-password"
		signOpts.BundlePath = bundlePath

		_, err := SignBlobWithOptions(ctx, payload, signOpts)
		require.Error(t, err)
	})

	t.Run("overwrite protection", func(t *testing.T) {
		t.Parallel()

		bundlePath := filepath.Join(t.TempDir(), "zarf.bundle.json")
		require.NoError(t, os.WriteFile(bundlePath, []byte("pre-existing"), 0o600))

		signOpts := DefaultSignBlobOptions()
		signOpts.Key = keyPath
		signOpts.Password = password
		signOpts.BundlePath = bundlePath
		signOpts.Overwrite = false

		_, err := SignBlobWithOptions(ctx, payload, signOpts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "already exists")
	})
}

func TestNewSignerKeypair(t *testing.T) {
	t.Parallel()

	t.Run("nil signer returns error", func(t *testing.T) {
		t.Parallel()
		_, err := NewSignerKeypair(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signer must not be nil")
	})

	t.Run("ecdsa keypair", func(t *testing.T) {
		t.Parallel()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		s, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
		require.NoError(t, err)
		kp, err := NewSignerKeypair(s)
		require.NoError(t, err)
		require.Equal(t, "ECDSA", kp.GetKeyAlgorithm())
		require.Equal(t, protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
		require.Equal(t, protocommon.HashAlgorithm_SHA2_256, kp.GetHashAlgorithm())
		require.NotEmpty(t, kp.GetHint())
		pem, err := kp.GetPublicKeyPem()
		require.NoError(t, err)
		require.Contains(t, pem, "PUBLIC KEY")

		sig, digest, err := kp.SignData(context.Background(), []byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, sig)
		require.NotEmpty(t, digest)
	})

	t.Run("rsa keypair", func(t *testing.T) {
		t.Parallel()
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		s, err := signature.LoadRSAPKCS1v15SignerVerifier(priv, crypto.SHA256)
		require.NoError(t, err)
		kp, err := NewSignerKeypair(s)
		require.NoError(t, err)
		require.Equal(t, "RSA", kp.GetKeyAlgorithm())
		require.Equal(t, protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, kp.GetSigningAlgorithm())
	})

	t.Run("ed25519 keypair", func(t *testing.T) {
		t.Parallel()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		s, err := signature.LoadED25519SignerVerifier(priv)
		require.NoError(t, err)
		kp, err := NewSignerKeypair(s)
		require.NoError(t, err)
		require.Equal(t, "ED25519", kp.GetKeyAlgorithm())
		require.Equal(t, protocommon.PublicKeyDetails_PKIX_ED25519, kp.GetSigningAlgorithm())
	})
}
