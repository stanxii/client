package stellar

import (
	"context"
	"testing"

	"github.com/keybase/client/go/externalstest"
	"github.com/keybase/client/go/kbtest"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/stellar1"
	insecureTriplesec "github.com/keybase/go-triplesec-insecure"
	"github.com/stretchr/testify/require"
)

func SetupTest(tb testing.TB, name string, depth int) (tc libkb.TestContext) {
	tc = externalstest.SetupTest(tb, name, depth+1)
	// use an insecure triplesec in tests
	tc.G.NewTriplesec = func(passphrase []byte, salt []byte) (libkb.Triplesec, error) {
		warner := func() { tc.G.Log.Warning("Installing insecure Triplesec with weak stretch parameters") }
		isProduction := func() bool {
			return tc.G.Env.GetRunMode() == libkb.ProductionRunMode
		}
		return insecureTriplesec.NewCipher(passphrase, salt, warner, isProduction)
	}
	return tc
}

func TestNoteRoundtrip(t *testing.T) {
	sk := randomSymmetricKey(t)
	pre := sampleNote()
	expect := pre.DeepCopy()
	encNote, err := noteEncryptHelper(context.Background(), pre, sk)
	require.NoError(t, err)
	post, err := noteDecryptHelper(context.Background(), encNote, sk)
	require.NoError(t, err)
	require.Equal(t, expect, post)
}

func TestNoteBadKey(t *testing.T) {
	sk := randomSymmetricKey(t)
	pre := sampleNote()
	encNote, err := noteEncryptHelper(context.Background(), pre, sk)
	require.NoError(t, err)
	sk[3] = 'c'
	_, err = noteDecryptHelper(context.Background(), encNote, sk)
	require.Error(t, err)
	require.Equal(t, "could not decrypt note secretbox", err.Error())
}

func TestNoteCorruptCiphertext(t *testing.T) {
	sk := randomSymmetricKey(t)
	pre := sampleNote()
	encNote, err := noteEncryptHelper(context.Background(), pre, sk)
	encNote.E[3] = 'c'
	require.NoError(t, err)
	_, err = noteDecryptHelper(context.Background(), encNote, sk)
	require.Error(t, err)
	require.Equal(t, "could not decrypt note secretbox", err.Error())
}

func randomSymmetricKey(t testing.TB) libkb.NaclSecretBoxKey {
	puk, err := libkb.GeneratePerUserKeySeed()
	require.NoError(t, err)
	symmetricKey, err := puk.DeriveSymmetricKey(libkb.DeriveReason("testing testing testing"))
	require.NoError(t, err)
	return symmetricKey
}

func sampleNote() stellar1.NoteContents {
	return stellar1.NoteContents{
		Version:   1,
		Note:      "wizbang",
		StellarID: stellar1.TransactionID("6653fc2fdbc42ad51ccbe77ee0a3c29e258a5513c62fdc532cbfff91ab101abf"),
	}
}

// Create n TestContexts with logged in users
// Returns (FakeUsers, TestContexts, CleanupFunction)
func setupNTests(t *testing.T, n int) ([]*kbtest.FakeUser, []*libkb.TestContext, func()) {
	return setupNTestsWithPukless(t, n, 0)
}

func setupNTestsWithPukless(t *testing.T, n, nPukless int) ([]*kbtest.FakeUser, []*libkb.TestContext, func()) {
	require.True(t, n > 0, "must create at least 1 tc")
	require.True(t, n >= nPukless, "more pukless users than total users requested")
	var fus []*kbtest.FakeUser
	var tcs []*libkb.TestContext
	for i := 0; i < n; i++ {
		tc := SetupTest(t, "wall", 1)
		tcs = append(tcs, &tc)
		if i >= n-nPukless {
			tc.Tp.DisableUpgradePerUserKey = true
		}
		fu, err := kbtest.CreateAndSignupFakeUser("wall", tc.G)
		require.NoError(t, err)
		fus = append(fus, fu)
	}
	cleanup := func() {
		for _, tc := range tcs {
			tc.Cleanup()
		}
	}
	for i, fu := range fus {
		t.Logf("U%d: %v %v", i, fu.Username, fu.GetUserVersion())
	}
	return fus, tcs, cleanup
}
