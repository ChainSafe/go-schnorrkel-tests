package schnorrkel

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func ExampleSecretKey_Sign() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := NewSigningContext(signingCtx, msg)
	verifyTranscript := NewSigningContext(signingCtx, msg)

	priv, pub, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}

	sig, err := priv.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	ok := pub.Verify(sig, verifyTranscript)
	if !ok {
		fmt.Println("failed to verify signature")
		return
	}

	fmt.Println("verified signature")
	// Output: verified signature
}

func ExamplePublicKey_Verify() {
	pub, err := NewPublicKeyFromHex("0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	if err != nil {
		panic(err)
	}

	sig, err := NewSignatureFromHex("0x4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	if err != nil {
		panic(err)
	}

	msg := []byte("this is a message")
	transcript := NewSigningContext(SigningContext, msg)
	ok := pub.Verify(sig, transcript)
	if !ok {
		fmt.Println("failed to verify signature")
		return
	}

	fmt.Println("verified signature")
	// Output: verified signature
}

func ExampleSignature() {
	msg := []byte("hello")
	signingCtx := []byte("example")

	signingTranscript := NewSigningContext(signingCtx, msg)

	sk, _, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}

	sig, err := sk.Sign(signingTranscript)
	if err != nil {
		panic(err)
	}

	fmt.Printf("0x%x", sig.Encode())
}

func TestSignAndVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok := pub.Verify(sig, transcript2)
	require.True(t, ok)
}

func TestVerify(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, pub, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	transcript2 := merlin.NewTranscript("hello")
	ok := pub.Verify(sig, transcript2)
	require.True(t, ok)

	transcript3 := merlin.NewTranscript("hello")
	ok = pub.Verify(sig, transcript3)
	require.True(t, ok)
}

func TestSignature_EncodeAndDecode(t *testing.T) {
	transcript := merlin.NewTranscript("hello")
	priv, _, err := GenerateKeypair()
	require.NoError(t, err)

	sig, err := priv.Sign(transcript)
	require.NoError(t, err)

	enc := sig.Encode()

	res := &Signature{}
	err = res.Decode(enc)
	require.NoError(t, err)

	s_exp := sig.s.Encode([]byte{})
	s_res := res.s.Encode([]byte{})

	r_exp := sig.r.Encode([]byte{})
	r_res := res.r.Encode([]byte{})

	require.Equal(t, s_exp, s_res)
	require.Equal(t, r_exp, r_res)
}

var SigningContext = []byte("substrate")

func TestVerify_rust(t *testing.T) {
	// test vectors from https://github.com/Warchant/sr25519-crust/blob/master/test/ds.cpp#L48
	pubhex, err := hex.DecodeString("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
	require.NoError(t, err)

	in := [32]byte{}
	copy(in[:], pubhex)

	pub := &PublicKey{}
	err = pub.Decode(in)
	require.NoError(t, err)

	msg := []byte("this is a message")
	sighex, err := hex.DecodeString("4e172314444b8f820bb54c22e95076f220ed25373e5c178234aa6c211d29271244b947e3ff3418ff6b45fd1df1140c8cbff69fc58ee6dc96df70936a2bb74b82")
	require.NoError(t, err)

	sigin := [64]byte{}
	copy(sigin[:], sighex)

	sig := &Signature{}
	err = sig.Decode(sigin)
	require.NoError(t, err)

	transcript := NewSigningContext(SigningContext, msg)
	ok := pub.Verify(sig, transcript)
	require.True(t, ok)
}
func StringToBytes(in string) ([]byte, error) {
	// remove [ and ] from string
	s := strings.Trim(in, "[")
	s = strings.Trim(s, "]")

	// split string into individual bytes
	split := strings.Split(s, ", ")
	output := make([]byte, len(split))

	for i := range output {
		// convert string to integer to then make into byte
		num, err := strconv.Atoi(split[i])
		if err != nil {
			return nil, err
		}
		output[i] = byte(num)
	}

	return output, nil
}

func ParseStdOut(out []byte) ([10]*merlin.Transcript, [10]*PublicKey, [10]*Signature, error) {
	// Rust file outputs 10 signatures
	var msgs [10]*merlin.Transcript
	var keys [10]*PublicKey
	var sigs [10]*Signature

	// output from Rust impl separated by \n
	split_out := strings.Split(string(out), "\n")

	// 10 sigs generated
	// need to parse context, msg, public key, and sig for each
	for i := 0; i < 10; i++ {
		// parse context
		ctx, err := StringToBytes(split_out[4*i])
		if err != nil {
			return msgs, keys, sigs, err
		}
		// parse message
		msg, err := StringToBytes(split_out[4*i+1])
		if err != nil {
			return msgs, keys, sigs, err
		}
		// parse public key bytes
		raw_pub_key_bytes, err := StringToBytes(split_out[4*i+2])
		if err != nil {
			return msgs, keys, sigs, err
		}
		// parse signature bytes
		raw_sig_bytes, err := StringToBytes(split_out[4*i+3])
		if err != nil {
			return msgs, keys, sigs, err
		}

		// use context and msg bytes to form signing context
		msgs[i] = NewSigningContext(ctx, msg)

		var pub_key_bytes [32]byte
		var sig_bytes [64]byte
		copy(pub_key_bytes[:], raw_pub_key_bytes)
		copy(sig_bytes[:], raw_sig_bytes)

		// attempt to decode public key bytes
		pub := &PublicKey{}
		err = pub.Decode(pub_key_bytes)
		if err != nil {
			return msgs, keys, sigs, err
		}
		keys[i] = pub

		// attempt to decode signature bytes
		sig := &Signature{}
		err = sig.Decode(sig_bytes)
		if err != nil {
			return msgs, keys, sigs, err
		}
		sigs[i] = sig
	}

	return msgs, keys, sigs, nil
}
func TestSignandVerify_differential(t *testing.T) {
	// first build using cargo
	// then run cargo run sign to generate 10 random signatures
	cargo := "cargo"
	build := "build"
	run := "run"
	path := "--manifest-path=test-rust/Cargo.toml"

	// cargo build
	cmd := exec.Command(cargo, build, path)
	_, err := cmd.Output()
	require.NoError(t, err)

	// cargo run sign will return 10 signatures from rust impl
	cmd = exec.Command(cargo, run, path, "sign")
	stdout, err := cmd.Output()
	require.NoError(t, err)

	// parse output from Rust impl into arrays of size 10
	msgs, pubs, sigs, err := ParseStdOut(stdout)
	require.NoError(t, err)

	// test valid signatures validate
	for i := 0; i < len(msgs); i++ {
		ok := pubs[i].Verify(sigs[i], msgs[i])
		require.True(t, ok)
	}
}

func TestSignandVerify_Bad_differential(t *testing.T) {
	// first build using cargo
	// then run cargo run sign to generate 10 random signatures
	cargo := "cargo"
	build := "build"
	run := "run"
	path := "--manifest-path=test-rust/Cargo.toml"

	// cargo build
	cmd := exec.Command(cargo, build, path)
	_, err := cmd.Output()
	require.NoError(t, err)

	// cargo run sign will return 10 signatures from rust impl
	cmd = exec.Command(cargo, run, path, "sign")
	stdout, err := cmd.Output()
	require.NoError(t, err)

	// parse output from Rust impl into arrays of size 10
	msgs, pubs, sigs, err := ParseStdOut(stdout)
	require.NoError(t, err)

	// use bad message and ensure signatures do not validate
	bad_msg := []byte("this is not the actual message that was signed")
	bad_ctx := []byte("this is an invalid context")
	bad_transcript := NewSigningContext(bad_ctx, bad_msg)
	for i := 0; i < len(msgs); i++ {
		ok := pubs[i].Verify(sigs[i], bad_transcript)
		require.False(t, ok)
	}
}
