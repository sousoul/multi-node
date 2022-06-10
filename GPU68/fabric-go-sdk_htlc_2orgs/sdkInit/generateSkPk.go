package sdkInit

// 生成组织的公私钥
// 使用了shim/bulletproof.go中初始椭圆曲线的代码，保证使用同一条椭圆曲线生成公私钥

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/mit-dci/zksigma"
	"github.com/mit-dci/zksigma/btcec"
	"math/big"
)

var EC CryptoParams
var VecLength = 8

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

type ECPoint struct {
	X, Y *big.Int
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

type OrgPkSk struct {
	Pk []zksigma.ECPoint
	Sk []*big.Int
}
// 结构体中的成员变量，只有首字母大写，才能在其定义的 package 以外访问。而在同一个 package 内，就不会有此限制。
// https://www.sunzhongwei.com/golang-access-struct-member-variable-times-wrong-always-refer-to-unexported-field-or-method-id
// 另外成员变量首字母不大写的话，无法转成json！
//https://blog.csdn.net/weixin_38386235/article/details/109243989

// 生成所有组织的公私钥
func Generate_sk_pk(orgNum int) OrgPkSk {
	orgpksk := OrgPkSk{}
	for i:=0; i<orgNum; i++{
		// 生成公私钥
		pk, sk := zksigma.KeyGen(ZKLedgerCurve.C, ZKLedgerCurve.H)
		orgpksk.Pk = append(orgpksk.Pk, pk)
		orgpksk.Sk = append(orgpksk.Sk, sk)
	}
	return orgpksk
}

// 生成单个组织的公私钥
func Generate_sk_pk_test() (zksigma.ECPoint, *big.Int) {
	// 生成公私钥
	pk, sk := zksigma.KeyGen(ZKLedgerCurve.C, ZKLedgerCurve.H)
	fmt.Println(pk)
	fmt.Println(sk)
	return pk, sk
}

type TxSpecification struct {
	Pk []zksigma.ECPoint
	R []*big.Int // 计算token用到的随机数
	Value []*big.Int // 交易额
}

type AuditSpecification struct {
	Pk []zksigma.ECPoint // 所有组织公钥
	Sk *big.Int // 支出方私钥

	R []*big.Int // txSpecification中的R
	ValueforRangeProof []*big.Int // 支出方是余额，其他方是交易额

	SpenderIdx int
}

// 用于初始化二维账本
func GetRforInit(zkpcp zksigma.ZKPCurveParams, spenderIdx int, receiverIdx int, asset []int64) TxSpecification {
	txSpe := TxSpecification{}
	totalR := big.NewInt(0)
	//var asset = [2]int64 {100, 100} // 初始化数组长度只能用常量
	orgNum := len(asset)

	for i := 0; i < orgNum; i++ {
		// 1. 生成每个org承诺中的r
		if i!=orgNum-1{
			r, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
			if err != nil {
				fmt.Errorf("生成随机数错误")
			}
			txSpe.R = append(txSpe.R, r)
			totalR = totalR.Add(totalR, r)
		}else {
			r := new(big.Int).Sub(ZKLedgerCurve.C.Params().N, totalR)
			r.Mod(r, ZKLedgerCurve.C.Params().N)
			txSpe.R = append(txSpe.R, r)
		}

		// 2. 初始化每个org的余额
		txSpe.Value = append(txSpe.Value, big.NewInt(asset[i]))
	}
	return txSpe
}

func GetR(zkpcp zksigma.ZKPCurveParams, value int64, orgNum int, spenderIdx int, receiverIdx int) TxSpecification {
	txSpe := TxSpecification{}
	totalR := big.NewInt(0)
	for i := 0; i < orgNum; i++ {
		// 1. 生成每个org承诺中的r
		if i!=orgNum-1{
			r, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
			if err != nil {
				fmt.Errorf("生成随机数错误")
			}
			txSpe.R = append(txSpe.R, r)
			totalR = totalR.Add(totalR, r)
		}else {
			r := new(big.Int).Sub(ZKLedgerCurve.C.Params().N, totalR)
			r.Mod(r, ZKLedgerCurve.C.Params().N)
			txSpe.R = append(txSpe.R, r)
		}
		if value < 0 {
			fmt.Errorf("value是一个正值，表示交易值")
		}
		// 2. 生成每个org的交易额
		if i==spenderIdx{
			txSpe.Value = append(txSpe.Value, big.NewInt(-value))
		} else if i==receiverIdx{
			txSpe.Value = append(txSpe.Value, big.NewInt(value))
		} else {
			txSpe.Value = append(txSpe.Value, big.NewInt(0))
		}
	}
	return txSpe
}

func CreateAuditSpecification(zkpcp zksigma.ZKPCurveParams, balance *big.Int, value int64, orgNum int, spenderIdx int, receiverIdx int) AuditSpecification {
	auditSpe := AuditSpecification{}
	if value < 0 {
		fmt.Errorf("value是一个正值，表示交易值")
	}
	// 生成每个org范围证明中的值
	for i:=0; i<orgNum; i++{
		if i==spenderIdx{
			auditSpe.ValueforRangeProof = append(auditSpe.ValueforRangeProof, balance)
		} else if i==receiverIdx {
			auditSpe.ValueforRangeProof = append(auditSpe.ValueforRangeProof, big.NewInt(value))
		} else {
			auditSpe.ValueforRangeProof = append(auditSpe.ValueforRangeProof, big.NewInt(0))
		}
	}
	return auditSpe
}