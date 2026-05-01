// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Icosa Consulting Inc.  Port of haakonnessjoen/MAC-Telnet (GPL-2.0).

package mactelnet

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
)

// EC-SRP on Curve25519 in Weierstrass form — port of mtwei.{h,c}.
//
// MAC-Telnet's EC-SRP uses Curve25519 expressed as a short Weierstrass
// curve  y² = x³ + ax + b  over GF(p), p = 2^255 - 19. This is birationally
// equivalent to the standard Curve25519 Montgomery form; the constants
// `w2m` and `m2w` translate x-coordinates between the two forms.
//
// We can't use crypto/elliptic.CurveParams here — its arithmetic assumes
// a = -3 mod p and panics on other coefficients — so we implement affine
// point ops directly on math/big. Performance is not a concern: a single
// auth handshake does ~3 scalar multiplications.
//
// Curve constants are the literal hex values from mtwei.c:mtwei_init.
// Anything we change here must be reviewed against that file or the
// handshake will silently produce wrong responses.
//
// Verification: this port has not yet been tested against a live RouterOS
// device. The math mirrors mtwei.c step-for-step but bit-exact equivalence
// can only be confirmed by capturing a successful handshake and feeding
// the same inputs through both implementations. See docs/STATUS.md M2.

type mtweiState struct {
	p   *big.Int // field prime: 2^255 - 19
	a   *big.Int // Weierstrass curve coefficient
	b   *big.Int // Weierstrass curve coefficient
	gx  *big.Int // generator x
	gy  *big.Int // generator y
	n   *big.Int // group order (prime subgroup)
	w2m *big.Int // Weierstrass-x → Montgomery-x offset
	m2w *big.Int // Montgomery-x → Weierstrass-x offset
}

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("mtwei: bad hex constant: " + s)
	}
	return n
}

func newMtweiState() *mtweiState {
	return &mtweiState{
		p:   mustHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
		a:   mustHex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144"),
		b:   mustHex("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864"),
		gx:  mustHex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a"),
		gy:  mustHex("5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14"),
		n:   mustHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
		w2m: mustHex("555555555555555555555555555555555555555555555555555555555552db9c"),
		m2w: mustHex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451"),
	}
}

// point is an affine-coordinate elliptic-curve point. Inf=true represents
// the point at infinity (group identity).
type point struct {
	X   *big.Int
	Y   *big.Int
	Inf bool
}

func (s *mtweiState) generator() *point {
	return &point{X: new(big.Int).Set(s.gx), Y: new(big.Int).Set(s.gy)}
}

// double returns 2P using the affine doubling formula:
//
//	λ = (3·Px² + a) · (2·Py)⁻¹ mod p
//	Rx = λ² - 2·Px mod p
//	Ry = λ·(Px - Rx) - Py mod p
func (s *mtweiState) double(pt *point) *point {
	if pt.Inf || pt.Y.Sign() == 0 {
		return &point{Inf: true}
	}

	pxSq := new(big.Int).Mul(pt.X, pt.X)
	num := new(big.Int).Mul(pxSq, big.NewInt(3))
	num.Add(num, s.a)
	num.Mod(num, s.p)

	den := new(big.Int).Lsh(pt.Y, 1) // 2·Py
	den.Mod(den, s.p)
	inv := new(big.Int).ModInverse(den, s.p)
	if inv == nil {
		return &point{Inf: true}
	}

	lam := new(big.Int).Mul(num, inv)
	lam.Mod(lam, s.p)

	rx := new(big.Int).Mul(lam, lam)
	rx.Sub(rx, pt.X)
	rx.Sub(rx, pt.X)
	rx.Mod(rx, s.p)

	ry := new(big.Int).Sub(pt.X, rx)
	ry.Mul(ry, lam)
	ry.Sub(ry, pt.Y)
	ry.Mod(ry, s.p)

	return &point{X: rx, Y: ry}
}

// add returns p1 + p2.
//
//	λ = (Qy - Py) · (Qx - Px)⁻¹ mod p
//	Rx = λ² - Px - Qx mod p
//	Ry = λ·(Px - Rx) - Py mod p
//
// Equal-X cases delegate to double or return infinity (p1 = -p2).
func (s *mtweiState) add(p1, p2 *point) *point {
	if p1.Inf {
		return &point{X: new(big.Int).Set(p2.X), Y: new(big.Int).Set(p2.Y), Inf: p2.Inf}
	}
	if p2.Inf {
		return &point{X: new(big.Int).Set(p1.X), Y: new(big.Int).Set(p1.Y), Inf: p1.Inf}
	}
	if p1.X.Cmp(p2.X) == 0 {
		if p1.Y.Cmp(p2.Y) == 0 {
			return s.double(p1)
		}
		return &point{Inf: true}
	}

	num := new(big.Int).Sub(p2.Y, p1.Y)
	num.Mod(num, s.p)
	den := new(big.Int).Sub(p2.X, p1.X)
	den.Mod(den, s.p)
	inv := new(big.Int).ModInverse(den, s.p)
	if inv == nil {
		return &point{Inf: true}
	}

	lam := new(big.Int).Mul(num, inv)
	lam.Mod(lam, s.p)

	rx := new(big.Int).Mul(lam, lam)
	rx.Sub(rx, p1.X)
	rx.Sub(rx, p2.X)
	rx.Mod(rx, s.p)

	ry := new(big.Int).Sub(p1.X, rx)
	ry.Mul(ry, lam)
	ry.Sub(ry, p1.Y)
	ry.Mod(ry, s.p)

	return &point{X: rx, Y: ry}
}

// scalarMult returns k·P via simple double-and-add over the bits of k.
// Not constant-time; this matches OpenSSL's generic EC_POINT_mul, which
// is not constant-time either for arbitrary curves. For a CLI tool used
// by an operator at the keyboard this is acceptable.
func (s *mtweiState) scalarMult(k *big.Int, pt *point) *point {
	res := &point{Inf: true}
	cur := &point{X: new(big.Int).Set(pt.X), Y: new(big.Int).Set(pt.Y), Inf: pt.Inf}
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			res = s.add(res, cur)
		}
		cur = s.double(cur)
	}
	return res
}

// liftX recovers a curve point from its x-coordinate and y-parity bit.
// y² = x³ + a·x + b mod p; pick the root whose lowest bit equals yParity.
// Returns false if x is not on the curve (no quadratic residue).
func (s *mtweiState) liftX(x *big.Int, yParity uint8) (*point, bool) {
	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, s.p)
	rhs.Mul(rhs, x)
	ax := new(big.Int).Mul(s.a, x)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, s.b)
	rhs.Mod(rhs, s.p)

	y := new(big.Int).ModSqrt(rhs, s.p)
	if y == nil {
		return nil, false
	}
	if uint8(y.Bit(0)) != yParity {
		y.Sub(s.p, y)
	}
	return &point{X: new(big.Int).Set(x), Y: y}, true
}

// tangle mutates target to fold in a hash-derived "validator point" and
// returns the validator interpreted as a big integer. Mirrors the static
// `tangle` function in mtwei.c.
//
// The loop on `edpx` is the same brute-force-until-on-curve dance upstream
// uses: SHA256 the candidate, add the m2w offset, try to lift it; if x
// isn't on the curve, increment the seed and retry. In practice this
// terminates in 1-2 iterations.
func (s *mtweiState) tangle(target *point, validator [mtweiValidatorLen]byte, negate uint8) *big.Int {
	v := new(big.Int).SetBytes(validator[:])

	valPt := s.scalarMult(v, s.generator())

	vpubX := new(big.Int).Add(valPt.X, s.w2m)
	vpubX.Mod(vpubX, s.p)

	var buf [32]byte
	vpubX.FillBytes(buf[:])
	seed := sha256.Sum256(buf[:])
	edpx := new(big.Int).SetBytes(seed[:])

	one := big.NewInt(1)
	var lifted *point
	for {
		var edpxBuf [32]byte
		edpx.FillBytes(edpxBuf[:])
		h := sha256.Sum256(edpxBuf[:])

		edpxm := new(big.Int).SetBytes(h[:])
		edpxm.Add(edpxm, s.m2w)
		edpxm.Mod(edpxm, s.p)

		if pt, ok := s.liftX(edpxm, negate); ok {
			lifted = pt
			break
		}
		edpx.Add(edpx, one)
	}

	sum := s.add(target, lifted)
	target.X = sum.X
	target.Y = sum.Y
	target.Inf = sum.Inf

	return v
}

// keygen produces a Curve25519-clamped private scalar and the matching
// 33-byte compressed public key (32-byte Montgomery x || 1-byte y-parity).
// If validator is non-nil, the resulting pubkey has it tangled in — used
// by the server side; clients pass nil here and pass validator to docrypto
// instead.
func (s *mtweiState) keygen(rand io.Reader, validator *[mtweiValidatorLen]byte) (*big.Int, [ecsrpPubkeyLen]byte, error) {
	var pubKey [ecsrpPubkeyLen]byte
	var raw [32]byte
	if _, err := io.ReadFull(rand, raw[:]); err != nil {
		return nil, pubKey, fmt.Errorf("mtwei: keygen rand: %w", err)
	}
	// RFC 7748 X25519 clamping. Inherited from upstream — preserves
	// compatibility with the implicit Curve25519 scalar shape even though
	// we operate on the Weierstrass form.
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64

	priv := new(big.Int).SetBytes(raw[:])
	pub := s.scalarMult(priv, s.generator())

	if validator != nil {
		s.tangle(pub, *validator, 0)
	}

	x := new(big.Int).Add(pub.X, s.w2m)
	x.Mod(x, s.p)
	x.FillBytes(pubKey[:32])
	pubKey[32] = uint8(pub.Y.Bit(0))

	return priv, pubKey, nil
}

// docrypto runs the EC-SRP client step and returns the 32-byte response
// the client sends in PASSWORD.
//
//   - serverKey: 33-byte server pubkey from PASSSALT
//   - clientKey: 33-byte client pubkey we put in our PASSSALT
//   - validator: 32-byte SRP validator (from mtweiID)
func (s *mtweiState) docrypto(priv *big.Int, serverKey, clientKey *[ecsrpPubkeyLen]byte, validator [mtweiValidatorLen]byte) ([ecsrpResponseLen]byte, error) {
	var out [ecsrpResponseLen]byte

	serverPubX := new(big.Int).SetBytes(serverKey[:32])
	serverPubX.Add(serverPubX, s.m2w)
	serverPubX.Mod(serverPubX, s.p)

	serverPub, ok := s.liftX(serverPubX, serverKey[32])
	if !ok {
		return out, fmt.Errorf("mtwei: server pubkey x-coordinate not on curve")
	}

	v := s.tangle(serverPub, validator, 1)

	// h = SHA256(client_key[0..32] || server_key[0..32]). The 33rd parity
	// byte is excluded — match upstream's `EVP_DigestUpdate(..., 32)`.
	hash := sha256.New()
	hash.Write(clientKey[:32])
	hash.Write(serverKey[:32])
	var hSum [32]byte
	copy(hSum[:], hash.Sum(nil))

	h := new(big.Int).SetBytes(hSum[:])

	// vh = (v·h + priv) mod n
	vh := new(big.Int).Mul(v, h)
	vh.Mod(vh, s.n)
	vh.Add(vh, priv)
	vh.Mod(vh, s.n)

	pt := s.scalarMult(vh, serverPub)

	zInput := new(big.Int).Add(pt.X, s.w2m)
	zInput.Mod(zInput, s.p)

	var zBytes [32]byte
	zInput.FillBytes(zBytes[:])

	final := sha256.New()
	final.Write(hSum[:])
	final.Write(zBytes[:])
	copy(out[:], final.Sum(nil))

	return out, nil
}
