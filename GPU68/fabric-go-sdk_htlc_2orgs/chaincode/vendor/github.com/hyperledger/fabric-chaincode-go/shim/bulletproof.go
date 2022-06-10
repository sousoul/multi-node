package shim

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/mit-dci/zksigma"
	"github.com/mit-dci/zksigma/btcec"
	//"github.com/btcsuite/btcd/btcec"
	"math"
	"math/big"
	"os"
	"strconv"
)

//package main

//import (
//"crypto/elliptic"
//"crypto/rand"
//"crypto/sha256"
//"encoding/binary"
//"fmt"
//"github.com/btcsuite/btcd/btcec"
//"math"
//"math/big"
//"os"
//"strconv"
//)

var EC CryptoParams
//var VecLength = 8
var VecLength = 64

type ECPoint struct {
	X, Y *big.Int
}

// Equal returns true if points p (self) and p2 (arg) are the  same.
func (p ECPoint) Equal(p2 ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// Mult multiplies point p by scalar s and returns the resulting point
func (p ECPoint) Mult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, EC.N)
	X, Y := EC.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	X, Y := EC.C.Add(p.X, p.Y, p2.X, p2.Y)
	return ECPoint{X, Y}
}

// Neg returns the additive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, EC.C.Params().P) // mod P is fine here because we're describing a curve point
	return ECPoint{p.X, modValue}
}

type CryptoParams struct {
	C   elliptic.Curve      // curve
	KC  *btcec.KoblitzCurve // curve
	BPG []ECPoint           // slice of gen 1 for BP
	BPH []ECPoint           // slice of gen 2 for BP
	N   *big.Int            // scalar prime
	U   ECPoint             // a point that is a fixed group element with an unknown discrete-log relative to g,h
	V   int                 // Vector length
	G   ECPoint             // G value for commitments of a single value
	H   ECPoint             // H value for commitments of a single value
}

func (c CryptoParams) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

/*
Vector Pedersen Commitment
Given an array of values, we commit the array with different generators
for each element and for each randomness.
*/

/*
Two Vector P Commit
Given an array of values, we commit the array with different generators
for each element and for each randomness.
*/
func TwoVectorPCommit(a []*big.Int, b []*big.Int) ECPoint {
	if len(a) != len(b) {
		fmt.Println("TwoVectorPCommit: Uh oh! Arrays not of the same length")
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	commitment := EC.Zero()

	for i := 0; i < EC.V; i++ {
		commitment = commitment.Add(EC.BPG[i].Mult(a[i])).Add(EC.BPH[i].Mult(b[i]))
	}

	return commitment
}

/*
Vector Pedersen Commitment with Gens
Given an array of values, we commit the array with different generators
for each element and for each randomness.
We also pass in the Generators we want to use
*/
func TwoVectorPCommitWithGens(G, H []ECPoint, a, b []*big.Int) ECPoint {
	if len(G) != len(H) || len(G) != len(a) || len(a) != len(b) {
		fmt.Println("TwoVectorPCommitWithGens: Uh oh! Arrays not of the same length")
		fmt.Printf("len(G): %d\n", len(G))
		fmt.Printf("len(H): %d\n", len(H))
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	commitment := EC.Zero()

	for i := 0; i < len(G); i++ {
		modA := new(big.Int).Mod(a[i], EC.N)
		modB := new(big.Int).Mod(b[i], EC.N)

		commitment = commitment.Add(G[i].Mult(modA)).Add(H[i].Mult(modB))
	}

	return commitment
}

// The length here always has to be a power of two
func InnerProduct(a []*big.Int, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		fmt.Println("InnerProduct: Uh oh! Arrays not of the same length")
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	c := big.NewInt(0)

	for i := range a {
		tmp1 := new(big.Int).Mul(a[i], b[i])
		c = new(big.Int).Add(c, new(big.Int).Mod(tmp1, EC.N))
	}

	return new(big.Int).Mod(c, EC.N)
}

func VectorAdd(v []*big.Int, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		fmt.Println("VectorAdd: Uh oh! Arrays not of the same length")
		fmt.Printf("len(v): %d\n", len(v))
		fmt.Printf("len(w): %d\n", len(w))
	}
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], w[i]), EC.N)
	}

	return result
}

func VectorHadamard(v, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		fmt.Println("VectorHadamard: Uh oh! Arrays not of the same length")
		fmt.Printf("len(v): %d\n", len(w))
		fmt.Printf("len(w): %d\n", len(v))
	}

	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], w[i]), EC.N)
	}

	return result
}

func VectorAddScalar(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], s), EC.N)
	}

	return result
}

func ScalarVectorMul(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], s), EC.N)
	}

	return result
}

/*
InnerProd Proof
This stores the argument values
*/
type InnerProdArg struct {
	L []ECPoint
	R []ECPoint
	A *big.Int
	B *big.Int

	Challenges []*big.Int
}

func GenerateNewParams(G, H []ECPoint, x *big.Int, L, R, P ECPoint) ([]ECPoint, []ECPoint, ECPoint) {
	nprime := len(G) / 2

	Gprime := make([]ECPoint, nprime)
	Hprime := make([]ECPoint, nprime)

	xinv := new(big.Int).ModInverse(x, EC.N)

	// Gprime = xinv * G[:nprime] + x*G[nprime:]
	// Hprime = x * H[:nprime] + xinv*H[nprime:]

	for i := range Gprime {
		//fmt.Printf("i: %d && i+nprime: %d\n", i, i+nprime)
		Gprime[i] = G[i].Mult(xinv).Add(G[i+nprime].Mult(x))
		Hprime[i] = H[i].Mult(x).Add(H[i+nprime].Mult(xinv))
	}

	x2 := new(big.Int).Mod(new(big.Int).Mul(x, x), EC.N)
	xinv2 := new(big.Int).ModInverse(x2, EC.N)

	Pprime := L.Mult(x2).Add(P).Add(R.Mult(xinv2)) // x^2 * L + P + xinv^2 * R

	return Gprime, Hprime, Pprime
}

/* Inner Product Argument
Proves that =c
This is a building block for BulletProofs
*/
func InnerProductProveSub(proof InnerProdArg, G, H []ECPoint, a []*big.Int, b []*big.Int, u ECPoint, P ECPoint) InnerProdArg {
	//time1 := time.Now().UnixNano()/ 1e6 //
	//fmt.Printf("Proof so far: %s\n", proof)
	if len(a) == 1 {
		// Prover sends a & b
		//fmt.Printf("a: %d && b: %d\n", a[0], b[0])
		proof.A = a[0]
		proof.B = b[0]
		return proof
	}
	//time2 := time.Now().UnixNano()/ 1e6 //
	curIt := int(math.Log2(float64(len(a)))) - 1
	//time3 := time.Now().UnixNano()/ 1e6 //
	nprime := len(a) / 2
	//fmt.Println(nprime)
	//fmt.Println(len(H))
	// InnerProduct需要big.Int间的乘法
	cl := InnerProduct(a[:nprime], b[nprime:]) // either this line
	cr := InnerProduct(a[nprime:], b[:nprime]) // or this line
	//time4 := time.Now().UnixNano()/ 1e6 //
	//fmt.Println("---------------耗时---------------")
	// TwoVectorPCommitWithGens需要ECpoint和big.Int相乘，以及ECpoint之间相加
	L := TwoVectorPCommitWithGens(G[nprime:], H[:nprime], a[:nprime], b[nprime:]).Add(u.Mult(cl))
	R := TwoVectorPCommitWithGens(G[:nprime], H[nprime:], a[nprime:], b[:nprime]).Add(u.Mult(cr))

	proof.L[curIt] = L
	proof.R[curIt] = R
	//fmt.Println("---------------耗时---------------")
	//time5 := time.Now().UnixNano()/ 1e6 //

	// prover sends L & R and gets a challenge
	s256 := sha256.Sum256([]byte(
		L.X.String() + L.Y.String() +
			R.X.String() + R.Y.String()))

	x := new(big.Int).SetBytes(s256[:])

	proof.Challenges[curIt] = x
	//time6 := time.Now().UnixNano()/ 1e6 //
	//fmt.Println("---------------耗时---------------")
	// GenerateNewParams需要ECpoint和big.Int相乘，以及ECpoint之间相加
	Gprime, Hprime, Pprime := GenerateNewParams(G, H, x, L, R, P)
	//fmt.Printf("Prover - Intermediate Pprime value: %s \n", Pprime)
	//fmt.Println("---------------耗时---------------")
	//time7 := time.Now().UnixNano()/ 1e6 //
	xinv := new(big.Int).ModInverse(x, EC.N)
	//time8 := time.Now().UnixNano()/ 1e6 //
	// or these two lines
	aprime := VectorAdd(
		ScalarVectorMul(a[:nprime], x),
		ScalarVectorMul(a[nprime:], xinv))
	bprime := VectorAdd(
		ScalarVectorMul(b[:nprime], xinv),
		ScalarVectorMul(b[nprime:], x))

	//time9 := time.Now().UnixNano()/ 1e6 //
	//fmt.Println("IPP", time2-time1, time3-time2, time4-time3, time5-time4, time6-time5, time7-time6,
	//	time8-time7, time9-time8)

	return InnerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime)
}

//rpresult.IPP = InnerProductProve(left, right, that, P, EC.U, EC.BPG, HPrime)
func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, P, U ECPoint, G, H []ECPoint) InnerProdArg {
	//time1 := time.Now().UnixNano()/ 1e6 //
	loglen := int(math.Log2(float64(len(a))))

	challenges := make([]*big.Int, loglen+1)
	Lvals := make([]ECPoint, loglen)
	Rvals := make([]ECPoint, loglen)

	runningProof := InnerProdArg{
		Lvals,
		Rvals,
		big.NewInt(0),
		big.NewInt(0),
		challenges}

	// randomly generate an x value from public data
	x := sha256.Sum256([]byte(P.X.String() + P.Y.String()))

	runningProof.Challenges[loglen] = new(big.Int).SetBytes(x[:])

	Pprime := P.Add(U.Mult(new(big.Int).Mul(new(big.Int).SetBytes(x[:]), c)))
	//time2 := time.Now().UnixNano()/ 1e6 //
	ux := U.Mult(new(big.Int).SetBytes(x[:]))
	//time3 := time.Now().UnixNano()/ 1e6 //
	//fmt.Printf("Prover Pprime value to run sub off of: %s\n", Pprime)
	//fmt.Println("IPP", time3-time2, time2-time1, time3-time1)
	return InnerProductProveSub(runningProof, G, H, a, b, ux, Pprime)
}

/* Inner Product Verify
Given a inner product proof, verifies the correctness of the proof
Since we're using the Fiat-Shamir transform, we need to verify all x hash computations,
all g' and h' computations
P : the Pedersen commitment we are verifying is a commitment to the innner product
ipp : the proof
*/

/* Inner Product Verify Fast
Given a inner product proof, verifies the correctness of the proof. Does the same as above except
we replace n separate exponentiations with a single multi-exponentiation.
*/

func InnerProductVerifyFast(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	//fmt.Println("Verifying Inner Product Argument")
	//fmt.Printf("Commitment Value: %s \n", P)
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	// check all challenges
	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		fmt.Println("IPVerify - Initial Challenge Failed")
		return false
	}

	for j := curIt - 1; j >= 0; j-- {
		Lval := ipp.L[j]
		Rval := ipp.R[j]

		// prover sends L & R and gets a challenge
		s256 := sha256.Sum256([]byte(
			Lval.X.String() + Lval.Y.String() +
				Rval.X.String() + Rval.Y.String()))

		chal2 := new(big.Int).SetBytes(s256[:])

		if ipp.Challenges[j].Cmp(chal2) != 0 {
			fmt.Println("IPVerify - Challenge verification failed at index " + strconv.Itoa(j))
			return false
		}
	}
	// begin computing

	curIt -= 1
	Pprime := P.Add(ux.Mult(c)) // line 6 from protocol 1

	tmp1 := EC.Zero()
	for j := curIt; j >= 0; j-- {
		x2 := new(big.Int).Exp(ipp.Challenges[j], big.NewInt(2), EC.N)
		x2i := new(big.Int).ModInverse(x2, EC.N)
		//fmt.Println(tmp1)
		tmp1 = ipp.L[j].Mult(x2).Add(ipp.R[j].Mult(x2i)).Add(tmp1)
		//fmt.Println(tmp1)
	}
	rhs := Pprime.Add(tmp1)
	//rhs=P+c*ux + L*xw+R*x2i ??29

	sScalars := make([]*big.Int, EC.V)
	invsScalars := make([]*big.Int, EC.V)

	for i := 0; i < EC.V; i++ {
		si := big.NewInt(1)
		for j := curIt; j >= 0; j-- {
			// original challenge if the jth bit of i is 1, inverse challenge otherwise
			chal := ipp.Challenges[j]
			if big.NewInt(int64(i)).Bit(j) == 0 {
				chal = new(big.Int).ModInverse(chal, EC.N)
			}
			// fmt.Printf("Challenge raised to value: %d\n", chal)
			si = new(big.Int).Mod(new(big.Int).Mul(si, chal), EC.N)
		}
		//fmt.Printf("Si value: %d\n", si)
		sScalars[i] = si
		invsScalars[i] = new(big.Int).ModInverse(si, EC.N)
	}

	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N)
	lhs := TwoVectorPCommitWithGens(G, H, ScalarVectorMul(sScalars, ipp.A), ScalarVectorMul(invsScalars, ipp.B)).Add(ux.Mult(ccalc))

	if !rhs.Equal(lhs) {
		fmt.Println("IPVerify - Final Commitment checking failed")
		fmt.Printf("Final rhs value: %s \n", rhs)
		fmt.Printf("Final lhs value: %s \n", lhs)
		return false
	}

	return true
}

// from here: https://play.golang.org/p/zciRZvD0Gr with a fix
func PadLeft(str, pad string, l int) string {
	strCopy := str
	for len(strCopy) < l {
		strCopy = pad + strCopy
	}

	return strCopy
}

func STRNot(str string) string {
	result := ""

	for _, i := range str {
		if i == '0' {
			result += "1"
		} else {
			result += "0"
		}
	}
	return result
}

func StrToBigIntArray(str string) []*big.Int {
	result := make([]*big.Int, len(str))

	for i := range str {
		t, success := new(big.Int).SetString(string(str[i]), 10)
		if success {
			result[i] = t
		}
	}

	return result
}

func reverse(l []*big.Int) []*big.Int {
	result := make([]*big.Int, len(l))

	for i := range l {
		result[i] = l[len(l)-i-1]
	}

	return result
}

func PowerVector(l int, base *big.Int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		result[i] = new(big.Int).Exp(base, big.NewInt(int64(i)), EC.N)
	}

	return result
}

func RandVector(l int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		x, err := rand.Int(rand.Reader, EC.N)
		check(err)
		result[i] = x
	}

	return result
}

func VectorSum(y []*big.Int) *big.Int {
	result := big.NewInt(0)

	for _, j := range y {
		result = new(big.Int).Mod(new(big.Int).Add(result, j), EC.N)
	}

	return result
}

type RangeProof struct {
	Comm ECPoint  // 是一个承诺
	A    ECPoint // Pedersen vector commitments
	S    ECPoint // Pedersen vector commitments
	T1   ECPoint // Pedersen commitments
	T2   ECPoint // Pedersen commitments
	Tau  *big.Int // 可能是文中的 a binding value rp.τ ？
	Th   *big.Int // 没搞懂是什么
	Mu   *big.Int // 没搞懂是什么
	IPP  InnerProdArg // an inner-product proof rp.IPP

	// challenges
	Cy *big.Int // Cy,Cz,Cx是三个哈希值
	Cz *big.Int
	Cx *big.Int
}

/*
Delta is a helper function that is used in the range proof
\delta(y, z) = (z-z^2)<1^n, y^n> - z^3<1^n, 2^n>
*/

func Delta(y []*big.Int, z *big.Int) *big.Int {
	result := big.NewInt(0)

	// (z-z^2)<1^n, y^n>
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), EC.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), EC.N)

	// z^3<1^n, 2^n>
	z3 := new(big.Int).Mod(new(big.Int).Mul(z2, z), EC.N)
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N), big.NewInt(1))
	t3 := new(big.Int).Mod(new(big.Int).Mul(z3, po2sum), EC.N)

	result = new(big.Int).Mod(new(big.Int).Sub(t2, t3), EC.N)

	return result
}

// Calculates (aL - z*1^n) + sL*x
func CalculateL(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	result := make([]*big.Int, len(aL))

	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)

	result = VectorAdd(tmp1, tmp2)

	return result
}

func CalculateR(aR, sR, y, po2 []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(po2) {
		fmt.Println("CalculateR: Uh oh! Arrays not of the same length")
		fmt.Printf("len(aR): %d\n", len(aR))
		fmt.Printf("len(sR): %d\n", len(sR))
		fmt.Printf("len(y): %d\n", len(y))
		fmt.Printf("len(po2): %d\n", len(po2))
	}

	result := make([]*big.Int, len(aR))

	z2 := new(big.Int).Exp(z, big.NewInt(2), EC.N)
	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11, tmp12))
	tmp2 := ScalarVectorMul(po2, z2)

	result = VectorAdd(tmp1, tmp2)

	return result
}

/*
RPProver : Range Proof Prove
Given a value v, provides a range proof that v is inside 0 to 2^64-1
*/
func RPProve(v *big.Int) (RangeProof, *big.Int) {
	//time1 := time.Now().UnixNano()/ 1e6 //
	rpresult := RangeProof{}

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))

	//v不能小于最小值0
	if v.Cmp(big.NewInt(0)) == -1 {
		fmt.Println("Value is below range! Not proving")
		os.Exit(1)
	}

	//v不能大于最大值
	if v.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N)) == 1 {
		fmt.Println("Value is above range! Not proving.")
		os.Exit(1)

	}

	// 1. 计算Pedersen承诺，所以这个就是Com_rp吗？？貌似只有这个承诺的消息是v
	gamma, err := rand.Int(rand.Reader, EC.N) // 产生一个在[0, N)范围的随机数
	check(err)
	comm := EC.G.Mult(v).Add(EC.H.Mult(gamma)) // Comm = v*G + gamma*H
	rpresult.Comm = comm

	//Comm = v*G + gamma*H

	// break up v into its bitwise representation
	//aL := 0
	//二进制、填充？？？？？？？？？
	aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", EC.V)))

	//取反？？？？？？？
	aR := VectorAddScalar(aL, big.NewInt(-1))
	//文档公式35？？？？？

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)

	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aL, aR).Add(EC.H.Mult(alpha))
	rpresult.A = A

	// Pedersen承诺？？？
	//A=(a*G + b*H) + alpha*H

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)

	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	rpresult.S = S

	// Pedersen承诺？？？
	//S=(a*G + b*H) + rho*H

	chal1s256 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	rpresult.Cy = cy
	//散列哈希
	//Cy = sha256(A)

	chal2s256 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	rpresult.Cz = cz
	//散列哈希
	//Cz = sha256(S)
	z2 := new(big.Int).Exp(cz, big.NewInt(2), EC.N)
	// need to generate l(X), r(X), and t(X)=

	/*
	   Java code on how to calculate t1 and t2
	       FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply),q); //powers of y
	       FieldVector l0 = aL.add(z.negate());
	       FieldVector l1 = sL;
	       FieldVector twoTimesZSquared = twos.times(zSquared);
	       FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
	       FieldVector r1 = sR.hadamard(ys);
	       BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
	       BigInteger t0 = k.add(zSquared.multiply(number));
	       BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
	       BigInteger t2 = l1.innerPoduct(r1);
	       PolyCommitment polyCommitment = PolyCommitment.from(base, t0, VectorX.of(t1, t2));
	*/
	PowerOfCY := PowerVector(EC.V, cy)
	// fmt.Println(PowerOfCY)
	l0 := VectorAddScalar(aL, new(big.Int).Neg(cz))
	// l1 := sL
	r0 := VectorAdd(
		VectorHadamard(
			PowerOfCY,
			VectorAddScalar(aR, cz)),
		ScalarVectorMul(
			PowerOfTwos,
			z2))
	r1 := VectorHadamard(sR, PowerOfCY)
	//time2 := time.Now().UnixNano()/ 1e6 //
	//calculate t0
	t0 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(v, z2), Delta(PowerOfCY, cz)), EC.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(sL, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(sL, r1)

	// given the t_i values, we can generate commitments to them
	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1)) //commitment to t1
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2)) //commitment to t2

	rpresult.T1 = T1
	//Pedersen承诺
	//T1 = t1*G + tau1*H
	rpresult.T2 = T2
	//Pedersen承诺
	//T2 = t2*G + tau2*H

	chal3s256 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	rpresult.Cx = cx
	//Cx = sha256(T1 + T2)

	left := CalculateL(aL, sL, cz, cx)
	right := CalculateR(aR, sR, PowerOfCY, PowerOfTwos, cz, cx)

	//一个是多项式加，展开的多项式
	thatPrime := new(big.Int).Mod( // t(x) = t0 + t1*x + t2*x^2
		new(big.Int).Add(
			t0,
			new(big.Int).Add(
				new(big.Int).Mul(
					t1, cx),
				new(big.Int).Mul(
					new(big.Int).Mul(cx, cx),
					t2))), EC.N)

	//一个是内积 t(x) = <l(x), r(x)>
	that := InnerProduct(left, right) // NOTE: BP Java implementation calculates this from the t_i

	// <l(x), r(x)> = t0 + t1*x + t2*x^2
	// thatPrime and that should be equal
	if thatPrime.Cmp(that) != 0 {
		fmt.Println("Proving -- Uh oh! Two diff ways to compute same value not working")
		fmt.Printf("\tthatPrime = %s\n", thatPrime.String())
		fmt.Printf("\tthat = %s \n", that.String())
	}

	rpresult.Th = thatPrime
	//Th = t0 + t1*x + t2*x^2

	taux1 := new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N)
	//t2*x^2
	taux2 := new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N)
	//t1*x
	taux3 := new(big.Int).Mod(new(big.Int).Mul(z2, gamma), EC.N)
	//z2*gamma
	taux := new(big.Int).Mod(new(big.Int).Add(taux1, new(big.Int).Add(taux2, taux3)), EC.N)
	//taux1+taux2+taux3

	rpresult.Tau = taux
	//Tau = taux1 + taux2 + taux3

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	rpresult.Mu = mu
	//Mu = alpha + rho*Cx

	HPrime := make([]ECPoint, len(EC.BPH))
	//time4 := time.Now().UnixNano()/ 1e6 //
	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}

	// for testing
	tmp1 := EC.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	tmp2 := EC.Zero()
	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowerOfCY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}
	//time5 := time.Now().UnixNano()/ 1e6 //
	//P1 := A.Add(S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.U.Mult(that)).Add(EC.H.Mult(mu).Neg())

	P := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)
	//fmt.Println(P1)
	//fmt.Println(P2)
	//time6 := time.Now().UnixNano()/ 1e6 //

	rpresult.IPP = InnerProductProve(left, right, that, P, EC.U, EC.BPG, HPrime)

	//time3 := time.Now().UnixNano()/ 1e6 //
	//fmt.Println(time2-time1, time3-time2, time3-time4, time3-time5, time3-time6)
	//fmt.Println(fmt.Sprintf("Rp总时间开销：%dms\n" +
	//	"IPP占比：%v\n", time3-time1, 100*float64(time3-time6)/float64(time3-time1)))
	return rpresult, gamma
}

func RPVerify(rp RangeProof) bool {
	// verify the challenges
	chal1s256 := sha256.Sum256([]byte(rp.A.X.String() + rp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])
	if cy.Cmp(rp.Cy) != 0 {
		fmt.Println("RPVerify - Challenge Cy failing!")
		return false
	}
	chal2s256 := sha256.Sum256([]byte(rp.S.X.String() + rp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])
	if cz.Cmp(rp.Cz) != 0 {
		fmt.Println("RPVerify - Challenge Cz failing!")
		return false
	}
	chal3s256 := sha256.Sum256([]byte(rp.T1.X.String() + rp.T1.Y.String() + rp.T2.X.String() + rp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])
	if cx.Cmp(rp.Cx) != 0 {
		fmt.Println("RPVerify - Challenge Cx failing!")
		return false
	}

	// given challenges are correct, very range proof
	PowersOfY := PowerVector(EC.V, cy)

	// t_hat * G + tau * H
	lhs := EC.G.Mult(rp.Th).Add(EC.H.Mult(rp.Tau))

	// z^2 * V + delta(y,z) * G + x * T1 + x^2 * T2
	rhs := rp.Comm.Mult(new(big.Int).Mul(cz, cz)).Add(
		EC.G.Mult(Delta(PowersOfY, cz))).Add(
		rp.T1.Mult(cx)).Add(
		rp.T2.Mult(new(big.Int).Mul(cx, cx)))

	if !lhs.Equal(rhs) {
		fmt.Println("RPVerify - Uh oh! Check line (63) of verification")
		fmt.Println(rhs)
		fmt.Println(lhs)
		return false
	}

	tmp1 := EC.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}
	//tmp1+=BPG*(-cz)

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))
	tmp2 := EC.Zero()
	// generate h'
	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		mi := new(big.Int).ModInverse(PowersOfY[i], EC.N)
		HPrime[i] = EC.BPH[i].Mult(mi)
	}

	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowersOfY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}

	//tmp2+=BPH*(val1+val2)

	// without subtracting this value should equal muCH + l[i]G[i] + r[i]H'[i]
	// we want to make sure that the innerproduct checks out, so we subtract it
	P := rp.A.Add(rp.S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.H.Mult(rp.Mu).Neg())
	//fmt.Println(P)
	//P=A+cx*S+tmp1+tmp2+(-Mu*H)

	if !InnerProductVerifyFast(rp.Th, P, EC.U, EC.BPG, HPrime, rp.IPP) {
		fmt.Println("RPVerify - Uh oh! Check line (65) of verification!")
		return false
	}

	return true
}

// Calculates (aL - z*1^n) + sL*x
func CalculateLMRP(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	result := make([]*big.Int, len(aL))

	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)

	result = VectorAdd(tmp1, tmp2)

	return result
}

func CalculateRMRP(aR, sR, y, zTimesTwo []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(zTimesTwo) {
		fmt.Println("CalculateR: Uh oh! Arrays not of the same length")
		fmt.Printf("len(aR): %d\n", len(aR))
		fmt.Printf("len(sR): %d\n", len(sR))
		fmt.Printf("len(y): %d\n", len(y))
		fmt.Printf("len(po2): %d\n", len(zTimesTwo))
	}

	result := make([]*big.Int, len(aR))

	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11, tmp12))

	result = VectorAdd(tmp1, zTimesTwo)

	return result
}

/*
DeltaMRP is a helper function that is used in the multi range proof
\delta(y, z) = (z-z^2)<1^n, y^n> - \sum_j z^3+j<1^n, 2^n>
*/

func DeltaMRP(y []*big.Int, z *big.Int, m int) *big.Int {
	result := big.NewInt(0)

	// (z-z^2)<1^n, y^n>
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), EC.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), EC.N)

	// \sum_j z^3+j<1^n, 2^n>
	// <1^n, 2^n> = 2^n - 1
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V/m)), EC.N), big.NewInt(1))
	t3 := big.NewInt(0)

	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(z, big.NewInt(3+int64(j)), EC.N)
		tmp1 := new(big.Int).Mod(new(big.Int).Mul(zp, po2sum), EC.N)
		t3 = new(big.Int).Mod(new(big.Int).Add(t3, tmp1), EC.N)
	}

	result = new(big.Int).Mod(new(big.Int).Sub(t2, t3), EC.N)

	return result
}

// NewECPrimeGroupKey returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKey(n int) CryptoParams {
	curValue := btcec.S256().Gx

	s256 := sha256.New()
	gen1Vals := make([]ECPoint, n)
	gen2Vals := make([]ECPoint, n)
	u := ECPoint{big.NewInt(0), big.NewInt(0)}
	cg := ECPoint{}
	ch := ECPoint{}

	j := 0
	confirmed := 0
	for confirmed < (2*n + 3) {
		s256.Write(new(big.Int).Add(curValue, big.NewInt(int64(j))).Bytes()) // 注意这里是+j，而zksigma中是固定+2

		potentialXValue := make([]byte, 33)
		binary.LittleEndian.PutUint32(potentialXValue, 2)
		for i, elem := range s256.Sum(nil) {
			potentialXValue[i+1] = elem
		}
		//fmt.Println(potentialXValue)
		gen2, err := btcec.ParsePubKey(potentialXValue, btcec.S256())// 每一次循环，会产生不同的gen2
		//if gen2!=nil{
		//	fmt.Println("comfirmed:", confirmed)
		//	fmt.Println(gen2.X, gen2.Y)
		//}
		if err == nil {
			if confirmed == 2*n { // once we've generated all g and h values then assign this to u
				u = ECPoint{gen2.X, gen2.Y}
				//fmt.Println("Got that U value")
			} else if confirmed == 2*n+1 {
				cg = ECPoint{gen2.X, gen2.Y}
				//fmt.Println("comfirmed:", confirmed)
				//fmt.Println("G:", cg)
				// comfirmed:17
				//19049299976918701640434378399416395322521814324735570823046957748159542780110 32970026245044992563886736445720684210429064727746262888414787291191552501274

			} else if confirmed == 2*n+2 {
				ch = ECPoint{gen2.X, gen2.Y}
			} else {
				if confirmed%2 == 0 {
					gen1Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//fmt.Println("new G Value")
				} else {
					gen2Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//fmt.Println("new H value")
				}
			}
			confirmed += 1
		}
		j += 1
	}

	return CryptoParams{
		btcec.S256(),
		btcec.S256(),
		gen1Vals,
		gen2Vals,
		btcec.S256().N,
		u,
		n,
		cg,
		ch}
}

// ZKLedgerCurve is a global cache for the curve and two generator points used in the various proof generation and verification functions.
var ZKLedgerCurve zksigma.ZKPCurveParams


func generateH2tothe() []zksigma.ECPoint {
	Hslice := make([]zksigma.ECPoint, 64)
	for i := range Hslice {
		m := big.NewInt(1 << uint(i))
		Hslice[i].X, Hslice[i].Y = ZKLedgerCurve.C.ScalarBaseMult(m.Bytes())
	}
	return Hslice
}

func init() {
	EC = NewECPrimeGroupKey(VecLength)
	// 使用bulletproof中的椭圆曲线参数
	ZKLedgerCurve = zksigma.ZKPCurveParams{
		C: btcec.S256(), // 这个本身和bulletproof中是一样的
		G: zksigma.ECPoint{EC.G.X, EC.G.Y},
		H: zksigma.ECPoint{EC.H.X, EC.H.Y},
	}
	ZKLedgerCurve.HPoints = generateH2tothe() // HPoints不清楚有什么用，zkledger中也没有用到
}