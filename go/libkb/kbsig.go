//
// Code used in populating JSON objects to generating Keybase-style
// signatures.
//
package libkb

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	jsonw "github.com/keybase/go-jsonw"
)

func clientInfo() *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("version", jsonw.NewString(CLIENT_VERSION))
	ret.SetKey("name", jsonw.NewString(GO_CLIENT_ID))
	return ret
}

func merkleRootInfo() (ret *jsonw.Wrapper) {
	if mc := G.MerkleClient; mc != nil {
		ret, _ = mc.LastRootToSigJson()
	}
	return ret
}

func (u *User) ToTrackingStatementKey(errp *error) *jsonw.Wrapper {
	ret := jsonw.NewDictionary()

	if !u.HasActiveKey() {
		*errp = fmt.Errorf("User %s doesn't have an active key", u.GetName())
	} else {
		fokid := u.GetEldestFOKID()
		ret.SetKey("kid", jsonw.NewString(fokid.Kid.String()))
		if fokid.Fp != nil {
			ret.SetKey("key_fingerprint", jsonw.NewString(fokid.Fp.String()))
		}
	}
	return ret
}

func (u *User) ToTrackingStatementPgpKeys(errp *error) *jsonw.Wrapper {
	keys := u.GetActivePgpKeys(true)
	if len(keys) == 0 {
		return nil
	}

	ret := jsonw.NewArray(len(keys))
	for i, k := range keys {
		kd := jsonw.NewDictionary()
		fokid := GenericKeyToFOKID(k)
		kd.SetKey("kid", jsonw.NewString(fokid.Kid.String()))
		if fokid.Fp != nil {
			kd.SetKey("key_fingerprint", jsonw.NewString(fokid.Fp.String()))
		}
		ret.SetIndex(i, kd)
	}
	return ret
}

func (u *User) ToTrackingStatementBasics(errp *error) *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("username", jsonw.NewString(u.name))
	if last_id_change, err := u.basics.AtKey("last_id_change").GetInt(); err == nil {
		ret.SetKey("last_id_change", jsonw.NewInt(last_id_change))
	}
	if id_version, err := u.basics.AtKey("id_version").GetInt(); err == nil {
		ret.SetKey("id_version", jsonw.NewInt(id_version))
	}
	return ret
}

func (u *User) ToTrackingStatementSeqTail() *jsonw.Wrapper {
	return u.sigs.AtKey("last")
}

func (u *User) ToTrackingStatement(w *jsonw.Wrapper) (err error) {

	track := jsonw.NewDictionary()
	track.SetKey("key", u.ToTrackingStatementKey(&err))
	if pgpkeys := u.ToTrackingStatementPgpKeys(&err); pgpkeys != nil {
		track.SetKey("pgp_keys", pgpkeys)
	}
	track.SetKey("seq_tail", u.ToTrackingStatementSeqTail())
	track.SetKey("basics", u.ToTrackingStatementBasics(&err))
	track.SetKey("id", jsonw.NewString(u.id.String()))
	track.SetKey("remote_proofs", u.IdTable.ToTrackingStatement())

	if err != nil {
		return
	}

	w.SetKey("type", jsonw.NewString("track"))
	w.SetKey("version", jsonw.NewInt(KEYBASE_SIGNATURE_V1))
	w.SetKey("track", track)
	return
}

func (u *User) ToUntrackingStatementBasics() *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("username", jsonw.NewString(u.name))
	return ret
}

func (u *User) ToUntrackingStatement(w *jsonw.Wrapper) (err error) {
	untrack := jsonw.NewDictionary()
	untrack.SetKey("basics", u.ToUntrackingStatementBasics())
	untrack.SetKey("id", jsonw.NewString(u.GetUid().String()))
	w.SetKey("type", jsonw.NewString("untrack"))
	w.SetKey("version", jsonw.NewInt(KEYBASE_SIGNATURE_V1))
	w.SetKey("untrack", untrack)
	return
}

func (u *User) ToKeyStanza(sk GenericKey, eldest *FOKID) (ret *jsonw.Wrapper, err error) {
	ret = jsonw.NewDictionary()
	ret.SetKey("uid", jsonw.NewString(u.id.String()))
	ret.SetKey("username", jsonw.NewString(u.name))
	ret.SetKey("host", jsonw.NewString(CANONICAL_HOST))

	if eldest == nil {
		eldest = u.GetEldestFOKID()
	}

	var signingKid KID
	if sk != nil {
		signingKid = sk.GetKid()
	} else {
		err = NoSecretKeyError{}
		return
	}

	if sk != nil {
		if fp := sk.GetFingerprintP(); fp != nil {
			ret.SetKey("fingerprint", jsonw.NewString(fp.String()))
			ret.SetKey("key_id", jsonw.NewString(fp.ToKeyId()))
		}
	}

	ret.SetKey("kid", jsonw.NewString(signingKid.String()))
	if eldest != nil {
		ret.SetKey("eldest_kid", jsonw.NewString(eldest.Kid.String()))
	}

	return
}

func (s *SocialProofChainLink) ToTrackingStatement() (*jsonw.Wrapper, error) {
	ret := s.BaseToTrackingStatement()
	err := remoteProofToTrackingStatement(s, ret)
	if err != nil {
		ret = nil
	}
	return ret, err
}

func (idt *IdentityTable) ToTrackingStatement() *jsonw.Wrapper {
	v := idt.activeProofs
	tmp := make([]*jsonw.Wrapper, 0, len(v))
	for _, proof := range v {
		if d, err := proof.ToTrackingStatement(); err != nil {
			G.Log.Warning("Problem with a proof: %s", err.Error())
		} else if d != nil {
			tmp = append(tmp, d)
		}
	}
	ret := jsonw.NewArray(len(tmp))
	for i, d := range tmp {
		ret.SetIndex(i, d)
	}
	return ret
}

func (g *GenericChainLink) BaseToTrackingStatement() *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("curr", jsonw.NewString(g.id.String()))
	ret.SetKey("sig_id", jsonw.NewString(g.GetSigId().ToString(true)))

	rkp := jsonw.NewDictionary()
	ret.SetKey("remote_key_proof", rkp)
	rkp.SetKey("state", jsonw.NewInt(g.GetProofState()))

	prev := g.GetPrev()
	var prev_val *jsonw.Wrapper
	if prev == nil {
		prev_val = jsonw.NewNil()
	} else {
		prev_val = jsonw.NewString(prev.String())
	}

	ret.SetKey("prev", prev_val)
	ret.SetKey("ctime", jsonw.NewInt64(g.unpacked.ctime))
	ret.SetKey("etime", jsonw.NewInt64(g.unpacked.etime))
	return ret
}

func remoteProofToTrackingStatement(s RemoteProofChainLink, base *jsonw.Wrapper) error {
	typ_s := s.TableKey()
	if i, found := REMOTE_SERVICE_TYPES[typ_s]; !found {
		return fmt.Errorf("No service type found for '%s' in proof %d",
			typ_s, s.GetSeqno())
	} else {
		base.AtKey("remote_key_proof").SetKey("proof_type", jsonw.NewInt(i))
	}
	base.AtKey("remote_key_proof").SetKey("check_data_json", s.CheckDataJson())
	base.SetKey("sig_type", jsonw.NewInt(SIG_TYPE_REMOTE_PROOF))
	return nil
}

func (u *User) ProofMetadata(ei int, signingKey GenericKey, eldest *FOKID) (ret *jsonw.Wrapper, err error) {

	var seqno int
	var prev_s string
	var key, prev *jsonw.Wrapper

	last_seqno := u.sigChain.GetLastKnownSeqno()
	last_link := u.sigChain.GetLastKnownId()
	if last_link == nil {
		seqno = 1
		prev = jsonw.NewNil()
	} else {
		seqno = int(last_seqno) + 1
		prev_s = last_link.String()
		prev = jsonw.NewString(prev_s)
	}

	if ei == 0 {
		ei = SIG_EXPIRE_IN
	}

	ret = jsonw.NewDictionary()
	ret.SetKey("tag", jsonw.NewString("signature"))
	ret.SetKey("ctime", jsonw.NewInt64(time.Now().Unix()))
	ret.SetKey("expire_in", jsonw.NewInt(ei))
	ret.SetKey("seqno", jsonw.NewInt(seqno))
	ret.SetKey("prev", prev)

	body := jsonw.NewDictionary()
	key, err = u.ToKeyStanza(signingKey, eldest)
	if err != nil {
		ret = nil
		return
	}
	body.SetKey("key", key)
	ret.SetKey("body", body)

	// Capture the most recent Merkle Root and also what kind of client
	// we're running.
	ret.SetKey("client", clientInfo())
	ret.SetKey("merkle_root", merkleRootInfo())

	return
}

func (u1 *User) TrackingProofFor(signingKey GenericKey, u2 *User) (ret *jsonw.Wrapper, err error) {
	ret, err = u1.ProofMetadata(0, signingKey, nil)
	if err == nil {
		err = u2.ToTrackingStatement(ret.AtKey("body"))
	}
	return
}

func (u1 *User) UntrackingProofFor(signingKey GenericKey, u2 *User) (ret *jsonw.Wrapper, err error) {
	ret, err = u1.ProofMetadata(0, signingKey, nil)
	if err == nil {
		err = u2.ToUntrackingStatement(ret.AtKey("body"))
	}
	return
}

func setDeviceOnBody(body *jsonw.Wrapper, key GenericKey, device Device) {
	kid := key.GetKid().String()
	device.Kid = &kid
	body.SetKey("device", device.Export())
}

func (u *User) KeyProof(arg Delegator) (ret *jsonw.Wrapper, pushType string, err error) {
	if arg.ExistingKey == nil {
		fokid := GenericKeyToFOKID(arg.NewKey)
		ret, err = u.eldestKeyProof(arg.NewKey, &fokid, arg.Device)
		pushType = ELDEST_TYPE
	} else {
		if arg.Sibkey {
			pushType = SIBKEY_TYPE
		} else {
			pushType = SUBKEY_TYPE
		}
		ret, err = u.delegateKeyProof(arg.NewKey, arg.ExistingKey, pushType, arg.Expire, arg.Device, arg.RevSig)
	}
	return
}

func (u *User) eldestKeyProof(signingKey GenericKey, eldest *FOKID, device *Device) (ret *jsonw.Wrapper, err error) {
	return u.selfProof(signingKey, eldest, device, ELDEST_TYPE)
}

func (u *User) selfProof(signingKey GenericKey, eldest *FOKID, device *Device, typ string) (ret *jsonw.Wrapper, err error) {
	ret, err = u.ProofMetadata(0, signingKey, eldest)
	if err != nil {
		return
	}
	body := ret.AtKey("body")
	body.SetKey("version", jsonw.NewInt(KEYBASE_SIGNATURE_V1))
	body.SetKey("type", jsonw.NewString(typ))

	if device != nil {
		setDeviceOnBody(body, signingKey, *device)
	}

	return
}

func (u *User) ServiceProof(signingKey GenericKey, typ ServiceType, remotename string) (ret *jsonw.Wrapper, err error) {
	ret, err = u.selfProof(signingKey, nil, nil, "web_service_binding")
	if err != nil {
		return
	}
	ret.AtKey("body").SetKey("service", typ.ToServiceJson(remotename))
	return
}

// SimpleSignJson marshals the given Json structure and then signs it.
func SignJson(jw *jsonw.Wrapper, key GenericKey) (out string, id *SigId, lid LinkId, err error) {
	var tmp []byte
	if tmp, err = jw.Marshal(); err != nil {
		return
	}
	out, id, err = key.SignToString(tmp)
	lid = ComputeLinkId(tmp)
	return
}

func NewReverseSigPayload(kid KID, u *User) ReverseSigPayload {
	return ReverseSigPayload{
		Ctime:       time.Now().Unix(),
		DelegatedBy: kid.String(),
		Uid:         u.GetUid().P(),
		Username:    u.GetName(),
	}
}

// revSig is optional.  Added for kex scenario.
func keyToProofJson(newkey GenericKey, typ string, signingKey GenericKey, revSig *ReverseSig, u *User) (ret *jsonw.Wrapper, err error) {
	ret = jsonw.NewDictionary()

	if typ == SIBKEY_TYPE {
		if revSig != nil {
			ret.SetKey("reverse_sig", jsonw.NewWrapper(*revSig))
		} else if newkey.CanSign() {
			var rs ReverseSig
			rsp := NewReverseSigPayload(signingKey.GetKid(), u)
			if rs.Sig, _, _, err = SignJson(jsonw.NewWrapper(rsp), newkey); err != nil {
				return
			}
			rs.Type = "kb"
			ret.SetKey("reverse_sig", jsonw.NewWrapper(rs))
		}
	}

	// For subkeys let's say who our parent is.  In this case it's the signing key,
	// though that can change in the future.
	if typ == SUBKEY_TYPE && signingKey != nil {
		ret.SetKey("parent_kid", jsonw.NewString(signingKey.GetKid().String()))
	}

	ret.SetKey("kid", jsonw.NewString(newkey.GetKid().String()))
	return
}

func (u *User) delegateKeyProof(newkey GenericKey, signingkey GenericKey, typ string, ei int, device *Device, revSig *ReverseSig) (ret *jsonw.Wrapper, err error) {
	ret, err = u.ProofMetadata(ei, signingkey, nil)
	if err != nil {
		return
	}
	body := ret.AtKey("body")
	body.SetKey("version", jsonw.NewInt(KEYBASE_SIGNATURE_V1))
	body.SetKey("type", jsonw.NewString(typ))

	if device != nil {
		setDeviceOnBody(body, newkey, *device)
	}

	var kp *jsonw.Wrapper
	if kp, err = keyToProofJson(newkey, typ, signingkey, revSig, u); err != nil {
		return
	}

	// 'typ' can be 'subkey' or 'sibkey'
	body.SetKey(typ, kp)
	return
}

// AuthenticationProof makes a JSON proof statement for the user that he can sign
// to prove a log-in to the system.  If successful, the server will return with
// a session token.
func (u *User) AuthenticationProof(key GenericKey, session string, ei int) (ret *jsonw.Wrapper, err error) {
	if ret, err = u.ProofMetadata(ei, key, nil); err != nil {
		return
	}
	body := ret.AtKey("body")
	body.SetKey("version", jsonw.NewInt(1))
	body.SetKey("type", jsonw.NewString("auth"))
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}
	body.SetKey("nonce", jsonw.NewString(hex.EncodeToString(nonce[:])))
	body.SetKey("session", jsonw.NewString(session))
	return
}
