// Copyright the Hyperledger Fabric contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package shim

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unicode/utf8"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	pb "github.com/hyperledger/fabric-protos-go/peer"

	"strconv"
	"github.com/mit-dci/zksigma"
	"math/big"

	"encoding/json"
	"chaincode/protobuf"

	"crypto/rand"
	"log"
	"time"
)

// 二维账本中的一行
type Transaction struct {
	ID    		string 		`json:"id"` // transaction identifier
	Zkrow		string		`json:"zkrow"`
}

type TxSpecification struct {
	Pk []zksigma.ECPoint
	R []*big.Int
	Value []*big.Int
}

type AuditSpecification struct {
	Pk []zksigma.ECPoint // 所有组织公钥
	Sk *big.Int // 支出方私钥

	R []*big.Int //
	ValueforRangeProof []*big.Int // 支出方是余额，其他方是交易额

	SpenderIdx int
}

// ChaincodeStub is an object passed to chaincode for shim side handling of
// APIs.
type ChaincodeStub struct {
	TxID                       string
	ChannelID                  string
	chaincodeEvent             *pb.ChaincodeEvent
	args                       [][]byte
	handler                    *Handler
	signedProposal             *pb.SignedProposal
	proposal                   *pb.Proposal
	validationParameterMetakey string

	// Additional fields extracted from the signedProposal
	creator   []byte
	transient map[string][]byte
	binding   []byte

	decorations map[string][]byte
}

// ChaincodeInvocation functionality

func newChaincodeStub(handler *Handler, channelID, txid string, input *pb.ChaincodeInput, signedProposal *pb.SignedProposal) (*ChaincodeStub, error) {
	stub := &ChaincodeStub{
		TxID:                       txid,
		ChannelID:                  channelID,
		args:                       input.Args,
		handler:                    handler,
		signedProposal:             signedProposal,
		decorations:                input.Decorations,
		validationParameterMetakey: pb.MetaDataKeys_VALIDATION_PARAMETER.String(),
	}

	// TODO: sanity check: verify that every call to init with a nil
	// signedProposal is a legitimate one, meaning it is an internal call
	// to system chaincodes.
	if signedProposal != nil {
		var err error

		stub.proposal = &pb.Proposal{}
		err = proto.Unmarshal(signedProposal.ProposalBytes, stub.proposal)
		if err != nil {

			return nil, fmt.Errorf("failed to extract Proposal from SignedProposal: %s", err)
		}

		// check for header
		if len(stub.proposal.GetHeader()) == 0 {
			return nil, errors.New("failed to extract Proposal fields: proposal header is nil")
		}

		// Extract creator, transient, binding...
		hdr := &common.Header{}
		if err := proto.Unmarshal(stub.proposal.GetHeader(), hdr); err != nil {
			return nil, fmt.Errorf("failed to extract proposal header: %s", err)
		}

		// extract and validate channel header
		chdr := &common.ChannelHeader{}
		if err := proto.Unmarshal(hdr.ChannelHeader, chdr); err != nil {
			return nil, fmt.Errorf("failed to extract channel header: %s", err)
		}
		validTypes := map[common.HeaderType]bool{
			common.HeaderType_ENDORSER_TRANSACTION: true,
			common.HeaderType_CONFIG:               true,
		}
		if !validTypes[common.HeaderType(chdr.GetType())] {
			return nil, fmt.Errorf(
				"invalid channel header type. Expected %s or %s, received %s",
				common.HeaderType_ENDORSER_TRANSACTION,
				common.HeaderType_CONFIG,
				common.HeaderType(chdr.GetType()),
			)
		}

		// extract creator from signature header
		shdr := &common.SignatureHeader{}
		if err := proto.Unmarshal(hdr.GetSignatureHeader(), shdr); err != nil {
			return nil, fmt.Errorf("failed to extract signature header: %s", err)
		}
		stub.creator = shdr.GetCreator()

		// extract trasient data from proposal payload
		payload := &pb.ChaincodeProposalPayload{}
		if err := proto.Unmarshal(stub.proposal.GetPayload(), payload); err != nil {
			return nil, fmt.Errorf("failed to extract proposal payload: %s", err)
		}
		stub.transient = payload.GetTransientMap()

		// compute the proposal binding from the nonce, creator and epoch
		epoch := make([]byte, 8)
		binary.LittleEndian.PutUint64(epoch, chdr.GetEpoch())
		digest := sha256.Sum256(append(append(shdr.GetNonce(), stub.creator...), epoch...))
		stub.binding = digest[:]

	}

	return stub, nil
}

/*密码学原语*/
// Pedersen承诺，comm = vG + rH
func (s *ChaincodeStub) Commitment(value *big.Int, r *big.Int) zksigma.ECPoint  {
	comm := zksigma.PedCommitR(ZKLedgerCurve, value, r)
	return comm
}

// 主要替换了标量相乘，保证计算承诺用到的G,H和计算其他密码学原语用到的G,H相同。
func (s *ChaincodeStub) Commitment_myself(value *big.Int, r *big.Int) zksigma.ECPoint{
	// modValue = value mod N
	modValue := new(big.Int).Mod(value, ZKLedgerCurve.C.Params().N)
	modRandom := new(big.Int).Mod(r, ZKLedgerCurve.C.Params().N)

	// mG, rH :: lhs, rhs
	x, y := ZKLedgerCurve.C.ScalarMult(ZKLedgerCurve.G.X, ZKLedgerCurve.G.Y, modValue.Bytes())
	lhs := zksigma.ECPoint{x, y}
	x, y = ZKLedgerCurve.C.ScalarMult(ZKLedgerCurve.H.X, ZKLedgerCurve.H.Y, modRandom.Bytes())
	rhs := zksigma.ECPoint{x, y}

	//mG + rH
	return ZKLedgerCurve.Add(lhs, rhs)
}

// 验证范围是否在[0, 2^t)区间内，在FabZK中t=64；注意：输入的val必须在该区间才能产生proof
func (s *ChaincodeStub) Create_bulletproof(m *big.Int) (RangeProof, *big.Int) {
	//m, _ := new(big.Int).SetString(val, 10) // 创建以10为基数的数字m
	RP_struct, r_RP := RPProve(m)
	return RP_struct, r_RP
}

func (s *ChaincodeStub) Verify_bulletproof(rtn RangeProof) bool {
	r:=RPVerify(rtn)

	fmt.Println("输出范围证明结果")
	fmt.Printf("Value is between 1 and 2^%d-1: %t\n",VecLength,r)


	fmt.Printf("=== Public parameters:\n")
	fmt.Printf(" Curve type:\tsecp256k1\n")
	fmt.Printf(" G:\t%s\n",EC.G)
	fmt.Printf(" H:\t%s\n",EC.H)
	fmt.Printf(" Curve b value:\t%s\n",EC.C.Params().B)
	fmt.Printf(" Curve prime value:\t%s\n",EC.C.Params().P)
	fmt.Printf(" Gi[0]:\t%s\n",EC.BPG[0])
	fmt.Printf(" Hi[0]:\t%s\n",EC.BPH[0])
	fmt.Printf(" Vector length:\t%d\n",EC.V)



	fmt.Printf("\n=== Proof\n")
	fmt.Printf("Challenge:\n")
	fmt.Printf(" Cx:\t%s\n",rtn.Cx)
	fmt.Printf(" Cy:\t%s\n",rtn.Cy)
	fmt.Printf(" Cz:\t%s\n",rtn.Cz)
	fmt.Printf("A:\t%s\n",rtn.A)
	fmt.Printf("S:\t%s\n",rtn.S)
	fmt.Printf("T1:\t%s\n",rtn.T1)
	fmt.Printf("T2:\t%s\n",rtn.T2)
	fmt.Printf("Tau:\t%s\n",rtn.Tau)
	fmt.Printf("Th:\t%s\n",rtn.Th)
	fmt.Printf("Mu:\t%s\n",rtn.Mu)

	fmt.Printf("\nIPP (Inner product proof):\n")
	fmt.Printf(" a:\t%s\n",rtn.IPP.A)
	fmt.Printf(" b:\t%s\n",rtn.IPP.B)
	fmt.Printf(" L[0]:\t%s\n",rtn.IPP.L[0])
	fmt.Printf(" R[0]:\t%s\n",rtn.IPP.R[0])
	fmt.Printf(" L[1]:\t%s\n",rtn.IPP.L[1])
	fmt.Printf(" R[1]:\t%s\n",rtn.IPP.R[1])

	return r
}

// 监管令牌，token = rPk
func (s *ChaincodeStub) Token(pk zksigma.ECPoint, r *big.Int) zksigma.ECPoint {
	rtoken := zksigma.CommitR(ZKLedgerCurve, pk, r)
	return rtoken
}

// Token' = T.(Com_{RP}/S)^{sk}, for otherwise
func (s *ChaincodeStub)TokenPrime(T, Com_RP, S zksigma.ECPoint, sk *big.Int) zksigma.ECPoint {
	res1 := ZKLedgerCurve.Sub(Com_RP, S) // Com_{RP}/S
	res2 := zksigma.CommitR(ZKLedgerCurve, res1, sk) // (Com_{RP}/S)^{sk}
	res3 := ZKLedgerCurve.Add(T, res2) // T.(Com_{RP}/S)^{sk}
	return res3
}

// Token'' = Token.(Com_{RP}/S)^{sk}, for spending org
func (s *ChaincodeStub)TokenDoublePrime(Token, Com_RP, S zksigma.ECPoint, sk *big.Int) zksigma.ECPoint {
	res1 := ZKLedgerCurve.Sub(Com_RP, S) // Com_{RP}/S
	res2 := zksigma.CommitR(ZKLedgerCurve, res1, sk) // (Com_{RP}/S)^{sk}
	res3 := ZKLedgerCurve.Add(Token, res2) // Token.(Com_{RP}/S)^{sk}
	return res3
}

/*FabZK chaincode API*/
func (s *ChaincodeStub)ZkPutState()  {
	// 计算承诺、token
	// 序列化
	// 调用原生Putstate, generate a write set
	fmt.Println("调用了ZkPutState!!!!!!!!!!!!!")
}

// 计算承诺、token，并可初始化账本中的余额
func (s *ChaincodeStub)ZkPutState_test(txSpeJsons string, key string) (string, error) {
	//log.Println(fmt.Sprintf("调用ZkPutState：%vms", time.Now().UnixNano()/ 1e6 ))
	txSpeStruct := TxSpecification{}
	json.Unmarshal([]byte(txSpeJsons), &txSpeStruct)

	// 定义账本中的一行，这里是以结构体指针的形式定义的
	first_row := &zkrow_package.Zkrow {
		Columns: map[string]*zkrow_package.OrgColumn{},
		IsValidAsset: false,
		IsValidBalCor: false,
	}
	orgNum := len(txSpeStruct.Value)
	for i:=0; i<orgNum; i++{
		comm := s.Commitment_myself(txSpeStruct.Value[i], txSpeStruct.R[i])
		token := s.Token(txSpeStruct.Pk[i], txSpeStruct.R[i])
		//comm := s.Commitment(txSpeStruct.Value[0], txSpeStruct.R[0])
		//token := s.Token(txSpeStruct.Pk[0], txSpeStruct.R[0])
		//fmt.Println(fmt.Sprintf("=========组织%d=========\n" +
		//	"Pedersen承诺：%v\n" +
		//	"令牌Token：%v\v", i+1, comm, token))

		// 序列化
		commJsons, err := json.Marshal(comm) // []byte
		if err != nil {
			fmt.Println(err.Error())
		}
		tokenJsons, err := json.Marshal(token) // []byte
		if err != nil {
			fmt.Println(err.Error())
		}

		//RP_struct := s.Create_bulletproof(big.NewInt(255)) // 生成范围证明
		////RP_struct := s.Create_bulletproof(txSpeStruct.Value[i].String()) // 生成范围证明
		////RP_proto := &zkrow_package.RangeProof{}
		////serialize_bulletproof(RP_struct, RP_proto) // 将RP_struct序列化到RP_proto
		//RP_byte, err := json.Marshal(RP_struct) // 测试能否直接将生成的范围证明序列为byte

		org_info := &zkrow_package.OrgColumn{
			Commitment: commJsons,
			AuditToken: tokenJsons,
			IsValidBalCor: false,
			IsValidAsset: false,
			//Rp: RP_byte,
		}

		// 在初始化账本时，也要初始化承诺之积S和token之积T
		if key=="0"{
			sJsons := commJsons
			tJsons := tokenJsons
			org_info.S = sJsons
			org_info.T = tJsons
		}

		org_name := "Org" + strconv.Itoa(i+1) // 定义一个组织名

		first_row.Columns[org_name] = org_info // 将组织信息添加到账本中的一行
	}

	zkrowdata, err := proto.Marshal(first_row) // protobuf序列化
	if err != nil {
		return "初始化二维账本失败", fmt.Errorf("Protobuf marshaling error: ", err)
	}

	err = s.PutState(key, zkrowdata) // 调用原生Putstate, generate a write set

	if err != nil {
		return "Putstate 失败", fmt.Errorf("Failed to initialize asset", err)
	}
	log.Println(fmt.Sprintf("调用ZkPutState完成：%vms", time.Now().UnixNano()/ 1e6 ))

	return "二维账本添加一行", nil
}
// 计算承诺、token和范围证明，并保存到世界状态
//func (s *ChaincodeStub)ZkPutState_test(txSpeJsons string, key string) (string, error) {
//	txSpeStruct := TxSpecification{}
//	json.Unmarshal([]byte(txSpeJsons), &txSpeStruct)
//
//	// 调用原生Putstate, generate a write set
//	// 定义账本中的一行，这里是以结构体指针的形式定义的
//	first_row := &zkrow_package.Zkrow {
//		Columns: map[string]*zkrow_package.OrgColumn{},
//		IsValidAsset: false,
//		IsValidBalCor: false,
//		//IsValidBalCor: true,
//	}
//	orgNum := len(txSpeStruct.Value)
//	fmt.Println("调用了ZkPutState!!!!!!!!!!!!!")
//	fmt.Println("长度", len(txSpeStruct.Value), len(txSpeStruct.R), len(txSpeStruct.Pk))
//	for i:=0; i<orgNum; i++{
//		comm := s.Commitment_myself(txSpeStruct.Value[i], txSpeStruct.R[i])
//		token := s.Token(txSpeStruct.Pk[i], txSpeStruct.R[i])
//		//comm := s.Commitment(txSpeStruct.Value[0], txSpeStruct.R[0])
//		//token := s.Token(txSpeStruct.Pk[0], txSpeStruct.R[0])
//		fmt.Println(comm)
//		fmt.Println(token)
//
//		// 序列化
//		commJsons, err := json.Marshal(comm) // []byte
//		if err != nil {
//			fmt.Println(err.Error())
//		}
//		tokenJsons, err := json.Marshal(token) // []byte
//		if err != nil {
//			fmt.Println(err.Error())
//		}
//
//		RP_struct := s.Create_bulletproof(big.NewInt(255)) // 生成范围证明
//		//RP_struct := s.Create_bulletproof(txSpeStruct.Value[i].String()) // 生成范围证明
//		//RP_proto := &zkrow_package.RangeProof{}
//		//serialize_bulletproof(RP_struct, RP_proto) // 将RP_struct序列化到RP_proto
//		RP_byte, err := json.Marshal(RP_struct) // 测试能否直接将生成的范围证明序列为byte
//
//		org_info := &zkrow_package.OrgColumn{
//			Commitment: commJsons,
//			AuditToken: tokenJsons,
//			IsValidBalCor: false,
//			IsValidAsset: false,
//			Rp: RP_byte,
//		}
//
//		org_name := "Org" + strconv.Itoa(i+1) // 定义一个组织名
//
//		first_row.Columns[org_name] = org_info // 将组织信息添加到账本中的一行
//	}
//
//	zkrowdata, err := proto.Marshal(first_row) // protobuf序列化
//	if err != nil {
//		return "初始化二维账本失败", fmt.Errorf("Protobuf marshaling error: ", err)
//	}
//
//	//err = s.PutState("newRow", zkrowdata) // 尝试跳过json
//	err = s.PutState(key, zkrowdata) // 尝试跳过json
//
//	if err != nil {
//		return "Putstate 失败", fmt.Errorf("Failed to initialize asset", err)
//	}
//	fmt.Println("success")
//
//	return "二维账本添加一行", nil
//
//}

// Compute range proofs and disjunctive proofs
// 支出方调用
func (s *ChaincodeStub)ZkAudit(auditSpeJsons string, key string) (string, error) {
	log.Println("调用ZkAudit")
	auditSpeStruct := AuditSpecification{}
	json.Unmarshal([]byte(auditSpeJsons), &auditSpeStruct)

	// 0. 读取账本中的当前行和上一行的内容
	zkrowdata, err := s.GetState(key)
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
	}
	if zkrowdata == nil {
		return "", fmt.Errorf("Asset not found: %s", key)
	}

	zkrow := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	keyInt, err := strconv.Atoi(key)
	key_last := strconv.Itoa(keyInt-1)
	zkrowdata_last, err := s.GetState(key_last) // 直接读取[]byte
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key_last, err)
	}
	if zkrowdata_last == nil {
		return "", fmt.Errorf("Asset not found: %s", key_last)
	}

	zkrow_last := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata_last, zkrow_last) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	//orgNum := 2
	//spenderidx := 0 // Org1是支出方
	orgNum := len(auditSpeStruct.ValueforRangeProof)
	spenderidx := auditSpeStruct.SpenderIdx
	for i:=0; i<orgNum; i++{
		// 组织名
		org_name := "Org" + strconv.Itoa(i+1)
		// 读取第j-1行的s, t
		s_last_json := zkrow_last.Columns[org_name].S
		s_last := zksigma.ECPoint{}
		err = json.Unmarshal(s_last_json, &s_last) // 必须传入引用！
		t_last_json := zkrow_last.Columns[org_name].T
		t_last := zksigma.ECPoint{}
		err = json.Unmarshal(t_last_json, &t_last)
		// 读取第j行的comm, token
		commJson := zkrow.Columns[org_name].Commitment
		comm := zksigma.ECPoint{}
		err = json.Unmarshal(commJson, &comm)
		tokenJson := zkrow.Columns[org_name].AuditToken
		token := zksigma.ECPoint{}
		err = json.Unmarshal(tokenJson, &token)
		// 计算第j行的s, t；乘除用加减代替，指数用乘法代替
		s_new := ZKLedgerCurve.Add(s_last, comm)
		t_new := ZKLedgerCurve.Add(t_last, token)
		log.Println("组织", i+1, "上一行的S和T：", s_last, t_last, "新的S和T：", s_new, t_new)

		// 序列化并保存
		sJsons, err := json.Marshal(s_new)
		if err != nil {
			fmt.Println(err.Error())
		}
		tJsons, err := json.Marshal(t_new)
		if err != nil {
			fmt.Println(err.Error())
		}
		zkrow.Columns[org_name].S = sJsons
		zkrow.Columns[org_name].T = tJsons
		if i==spenderidx{
			// 计算支出方
			// 1. 创建范围证明
			balance := auditSpeStruct.ValueforRangeProof[i]
			RP_struct, r_RP := s.Create_bulletproof(balance) // 生成余额的范围证明！

			// 这里有两种处理，a是用protobuf生成RP_proto，b是用JSON生成RP_btye
			// a. 将RP_struct序列化到RP_proto
			RP_proto := &zkrow_package.RangeProof{}
			serialize_bulletproof(RP_struct, RP_proto)

			// b. 测试能否直接将生成的范围证明序列为byte
			//RP_byte, err := json.Marshal(RP_struct)
			//if err != nil {
			//	fmt.Println(err.Error())
			//}

			// 2. 计算Token', Token''
			com_rp := zksigma.ECPoint{RP_struct.Comm.X, RP_struct.Comm.Y}  // 从范围证明中得到Com_{RP}
			tokenPrime := zksigma.CommitR(ZKLedgerCurve, auditSpeStruct.Pk[i], r_RP)
			sk_spender, err := rand.Int(rand.Reader, ZKLedgerCurve.C.Params().N) // 支出方不能使用自己的私钥，用随机数代替
			if err != nil {
				panic(err)
			}
			tokenPrimeJsons, err := json.Marshal(tokenPrime) // []byte
			if err != nil {
				fmt.Println(err.Error())
			}
			tokenDoublePrime := s.TokenDoublePrime(token, com_rp, s_new, sk_spender)
			tokenDoublePrimeJsons, err := json.Marshal(tokenDoublePrime) // []byte
			if err != nil {
				fmt.Println(err.Error())
			}

			// 3. 创建DZKP
			G1 := ZKLedgerCurve.Sub(s_new, com_rp) // g1 = s/com_{RP}
			Y1 := ZKLedgerCurve.Sub(t_new, tokenPrime) // y1 = t/token'
			G2 := auditSpeStruct.Pk[i] // g2 = pk，注意这里是支出方自己的公钥
			Y2 := ZKLedgerCurve.Sub(token, tokenDoublePrime) // g2 = token/token''
			x1 := auditSpeStruct.Sk // x1 = sk
			proof, err := zksigma.NewDisjunctiveProof(ZKLedgerCurve, G1, Y1, G2, Y2, x1, 0) // 支出方要证g1^x1 = y1, x1=sk
			if err!=nil{
				fmt.Println("dzkp报错：", err)
			}
			log.Println("析取证明：", proof)
			log.Println("G1,Y1,G2,Y2,x1", G1,Y1,G2,Y2,x1)
			log.Println("组织",i+1, "验证下是不是不一样", s.Token(G1, x1), Y1)

			proofBytes := proof.Bytes() // 若g1^x1 ≠ y1，即x1是错误的值，则proof是空的，在这一步序列化时会报错
			G1Jsons, err := json.Marshal(G1)
			if err != nil {
				fmt.Println(err.Error())
			}
			Y1Jsons, err := json.Marshal(Y1)
			if err != nil {
				fmt.Println(err.Error())
			}
			G2Jsons, err := json.Marshal(G2)
			if err != nil {
				fmt.Println(err.Error())
			}
			Y2Jsons, err := json.Marshal(Y2)
			if err != nil {
				fmt.Println(err.Error())
			}
			//test, err = proof.Verify(ZKLedgerCurve, G1, Y1, G2, Y2)
			//fmt.Println("DZKP验证结果：", test)

			// 4. 将Bulletproof, token', token'', DZKP保存到世界状态
			zkrow.Columns[org_name].TokenPrime = tokenPrimeJsons
			zkrow.Columns[org_name].TokenDoublePrime = tokenDoublePrimeJsons
			//zkrow.Columns[org_name].Rp = RP_byte
			zkrow.Columns[org_name].Rp = RP_proto
			dzkp := &zkrow_package.DisjunctiveProof{}
			dzkp.Proof = proofBytes
			dzkp.G1 = G1Jsons
			dzkp.Y1 = Y1Jsons
			dzkp.G2 = G2Jsons
			dzkp.Y2 = Y2Jsons
			zkrow.Columns[org_name].Dzkp = dzkp

		} else {
			// 计算其他方
			// 1. 创建范围证明
			value := auditSpeStruct.ValueforRangeProof[i]
			RP_struct, r_RP := s.Create_bulletproof(value) // 生成交易值的范围证明！

			// 这里有两种处理，a是用protobuf生成RP_proto，b是用JSON生成RP_btye
			// a. 将RP_struct序列化到RP_proto
			RP_proto := &zkrow_package.RangeProof{}
			serialize_bulletproof(RP_struct, RP_proto)

			// b. 直接将生成的范围证明序列为byte
			//RP_byte, err := json.Marshal(RP_struct) // 测试能否直接将生成的范围证明序列为byte
			//if err != nil {
			//	fmt.Println(err.Error())
			//}

			// 2. 计算Token', Token''
			com_rp := zksigma.ECPoint{RP_struct.Comm.X, RP_struct.Comm.Y}  // 从范围证明中得到Com_{RP}
			sk_other, err := rand.Int(rand.Reader, ZKLedgerCurve.C.Params().N) // 支出方不知道其他方的私钥，用随机数代替
			if err != nil {
				panic(err)
			}
			tokenPrime := s.TokenPrime(t_new, com_rp, s_new, sk_other)
			tokenPrimeJsons, err := json.Marshal(tokenPrime) // []byte
			if err != nil {
				fmt.Println(err.Error())
			}
			tokenDoublePrime := zksigma.CommitR(ZKLedgerCurve, auditSpeStruct.Pk[i], r_RP)
			tokenDoublePrimeJsons, err := json.Marshal(tokenDoublePrime) // []byte
			if err != nil {
				fmt.Println(err.Error())
			}

			// 3. 创建DZKP
			G1 := ZKLedgerCurve.Sub(s_new, com_rp) // g1 = s/com_{RP}
			Y1 := ZKLedgerCurve.Sub(t_new, tokenPrime) // y1 = t/token'
			G2 := auditSpeStruct.Pk[i] // g2 = pk，注意这里是各自的公钥
			Y2 := ZKLedgerCurve.Sub(token, tokenDoublePrime) // g2 = token/token''
			//x2 := auditSpeStruct.R[i].Sub(auditSpeStruct.R[i], r_RP) // x2 = r-r_{RP}
			var tmpX2 big.Int
			x2 := tmpX2.Sub(auditSpeStruct.R[i], r_RP)
			modX2 := new(big.Int).Mod(x2, ZKLedgerCurve.C.Params().N)

			fmt.Println("组织",i+1, "验证下是不是不一样", s.Token(G2, modX2), Y2)
			proof, err := zksigma.NewDisjunctiveProof(ZKLedgerCurve, G1, Y1, G2, Y2, modX2, 1) // 其他方要证g2^x2 = y2, x2=r-r_{RP}
			if err!=nil{
				fmt.Println("dzkp报错：", err)
			}
			log.Println("析取证明：", proof)
			log.Println("G1,Y1,G2,Y2,x2", G1,Y1,G2,Y2,modX2)

			proofBytes := proof.Bytes() // 若g1^x1 ≠ y1，即x1是错误的值，则proof是空的，在这一步序列化时会报错
			G1Jsons, err := json.Marshal(G1)
			if err != nil {
				fmt.Println(err.Error())
			}
			Y1Jsons, err := json.Marshal(Y1)
			if err != nil {
				fmt.Println(err.Error())
			}
			G2Jsons, err := json.Marshal(G2)
			if err != nil {
				fmt.Println(err.Error())
			}
			Y2Jsons, err := json.Marshal(Y2)
			if err != nil {
				fmt.Println(err.Error())
			}
			//res, err := proof.Verify(ZKLedgerCurve, G1, Y1, G2, Y2)
			//fmt.Println("DZKP验证结果：", res)

			// 4. 将Bulletproof, token', token'', DZKP保存到世界状态
			zkrow.Columns[org_name].TokenPrime = tokenPrimeJsons
			zkrow.Columns[org_name].TokenDoublePrime = tokenDoublePrimeJsons
			//zkrow.Columns[org_name].Rp = RP_byte
			zkrow.Columns[org_name].Rp = RP_proto
			dzkp := &zkrow_package.DisjunctiveProof{}
			dzkp.Proof = proofBytes
			dzkp.G1 = G1Jsons
			dzkp.Y1 = Y1Jsons
			dzkp.G2 = G2Jsons
			dzkp.Y2 = Y2Jsons
			zkrow.Columns[org_name].Dzkp = dzkp
		}
	}
	zkrowdata_audit, err := proto.Marshal(zkrow) // zkrowdata在调用audit()之后多了一些内容，成为了zkrowdata_audit
	if err != nil {
		return "", fmt.Errorf("Protobuf marshaling error: ", err)
	}

	err = s.PutState(key, zkrowdata_audit) // 尝试跳过json
	if err != nil {
		return "Putstate 失败", fmt.Errorf("Failed to initialize asset", err)
	}

	return "生成范围证明、析取证明", nil
	//return strconv.FormatBool(test), nil
}

func (s *ChaincodeStub)ZkVerifyOne(key string, orgNum int, sk *big.Int, org_name string, value *big.Int) (string, error) {
	zkrowdata, err := s.GetState(key) // 直接读取[]byte
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
	}
	if zkrowdata == nil {
		return "", fmt.Errorf("Asset not found: %s", key)
	}

	//// 改成轮询查询，以适用于并发环境
	//zkrowdata, err := s.GetState(key) // 直接读取[]byte
	//for {
	//	//if err != nil {
	//	//	return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
	//	//}
	//	if zkrowdata != nil {
	//		break
	//	}
	//	//time.Sleep(time.Millisecond*20)
	//	zkrowdata, err = s.GetState(key) // 直接读取[]byte
	//}

	zkrow := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	// 阶段一：验证Proof of Balance和Proof of Correctness
	// 1. Proof of Balance:
	//commJson := zkrow.Columns["Org1"].Commitment
	//commSum := zksigma.ECPoint{}
	//err = json.Unmarshal(commJson, &commSum)
	//fmt.Println("承诺之和", commSum)
	//for i:=1; i<orgNum; i++{
	//	// 读取承诺
	//	org_name := "Org" + strconv.Itoa(i+1)
	//	commJson := zkrow.Columns[org_name].Commitment
	//	comm := zksigma.ECPoint{}
	//	err = json.Unmarshal(commJson, &comm)
	//	// 求和
	//	commSum = ZKLedgerCurve.Add(commSum, comm)
	//	fmt.Println("承诺之和", commSum)
	//}
	//fmt.Println("承诺之和", commSum)
	//res1 := commSum.Equal(zksigma.ECPoint{big.NewInt(0), big.NewInt(0)}) // bool
	//fmt.Println("Proof of Balance:", res1)

	// 1. Proof of Balance:
	commSum := zksigma.ECPoint{big.NewInt(0),big.NewInt(0)}
	for i:=0; i<orgNum; i++{
		org_name := "Org" + strconv.Itoa(i+1)
		commJson := zkrow.Columns[org_name].Commitment
		comm := zksigma.ECPoint{}
		err := json.Unmarshal(commJson, &comm)
		if err != nil {
			fmt.Println(err.Error())
		}
		commSum = ZKLedgerCurve.Add(commSum, comm) // 求和
		fmt.Println(fmt.Sprintf("=========前%d个组织的承诺之和：=========\n" +
			"%v", i+1, commSum))
		//fmt.Println(commSum)
	}
	res1 := commSum.Equal(zksigma.ECPoint{big.NewInt(0), big.NewInt(0)}) // bool
	fmt.Println("Proof of Balance:", res1)

	// 2. Proof of Correctness:
	fmt.Println("私钥：", sk)
	tokenJsons := zkrow.Columns[org_name].AuditToken
	token := zksigma.ECPoint{}
	err = json.Unmarshal(tokenJsons, &token)
	commJson := zkrow.Columns[org_name].Commitment
	comm := zksigma.ECPoint{}
	err = json.Unmarshal(commJson, &comm)

	step1 := zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.G, sk) // g^{sk}
	step2 := zksigma.CommitR(ZKLedgerCurve, step1, value) // g^{sk.u}
	leftSide := ZKLedgerCurve.Add(token, step2) // token.g^{sk.u}
	rightSide := zksigma.CommitR(ZKLedgerCurve, comm, sk) // Com^{sk}
	res2 := leftSide.Equal(rightSide)
	fmt.Println(fmt.Sprintf("=========%s验证承诺正确性=========", org_name))
	fmt.Println("公式（3.4）左侧:", leftSide, "公式（3.4）右侧:", rightSide)
	fmt.Println("左侧==右侧，承诺计算正确！")

	//// 2. Proof of Correctness:
	//sk := orgPkSk.Sk[i]
	//value := txSpe.Value[i]
	//tokenJsons := zkrow.Columns[org_name].AuditToken
	//token := zksigma.ECPoint{}
	//err := json.Unmarshal(tokenJsons, &token)
	//if err != nil {
	//	fmt.Println(err.Error())
	//}
	//commJson := zkrow.Columns[org_name].Commitment
	//comm := zksigma.ECPoint{}
	//err = json.Unmarshal(commJson, &comm)
	//tt3 = time.Now().UnixNano()/ 1e3 //
	//step1 := zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.G, sk) // g^{sk}
	//step2 := zksigma.CommitR(ZKLedgerCurve, step1, value) // g^{sk.u}
	//leftSide := ZKLedgerCurve.Add(token, step2) // token.g^{sk.u}
	//rightSide := zksigma.CommitR(ZKLedgerCurve, comm, sk) // Com^{sk}
	//res2 := leftSide.Equal(rightSide)
	//fmt.Println("Proof of Correctness:", res2)
	//tt4 = time.Now().UnixNano()/ 1e3 //


	// 3. 更新OrgColumn.isValidBalCor和zkrow.isValidBalCor
	zkrow.Columns[org_name].IsValidBalCor = res1 && res2
	zkrow.IsValidBalCor = zkrow.IsValidBalCor && zkrow.Columns[org_name].IsValidBalCor

	//if (res1 && res2) ==true{
	//	return "Proof of Balance and Proof of Correctness pass！", nil
	//}else {
	//	if res1 == false && res2 == true{
	//		return "Proof of Balance not pass!! Check Proof of Balance and Proof of Correctness!", nil
	//	}else if res1 == true && res2 == false{
	//		return "Proof of Correctness not pass!! Check Proof of Balance and Proof of Correctness!", nil
	//	}
	//	return "Not pass!! Check Proof of Balance and Proof of Correctness!", nil
	//}
	if (res1 && res2) ==true{
		return fmt.Sprintf("交易金额平衡性、承诺正确性均通过"), nil
	}else {
		if res1 == false && res2 == true{
			return "Proof of Balance not pass!! Check Proof of Balance and Proof of Correctness!", nil
		}else if res1 == true && res2 == false{
			return "Proof of Correctness not pass!! Check Proof of Balance and Proof of Correctness!", nil
		}
		return "Not pass!! Check Proof of Balance and Proof of Correctness!", nil
	}
}

// 由其他组织来调用，完成第二个验证阶段中的范围证明、dzkp、补充证明
func (s *ChaincodeStub)ZkVerifyTwo(key string, orgNum int, org_name string, sk *big.Int) (string, error) {
	zkrowdata, err := s.GetState(key) // 直接读取[]byte
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
	}
	if zkrowdata == nil {
		return "", fmt.Errorf("Asset not found: %s", key)
	}

	zkrow := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	// 阶段二：验证范围证明和DZKP
	// 1. 范围证明

	// a. JSON反序列化
	//RP_byte_ := zkrow.Columns[org_name].Rp
	//RP_struct_2 := &RangeProof{}
	//err = json.Unmarshal(RP_byte_, RP_struct_2)

	// b. protobuf反序列化
	RP_proto_ := zkrow.Columns[org_name].Rp
	RP_struct_2 := &RangeProof{}
	deserialize_bulletproof(RP_proto_, RP_struct_2)

	res1 := s.Verify_bulletproof(*RP_struct_2)
	//if res1 ==true{
	//	return "范围证明验证通过！", nil
	//}else {
	//	return "范围证明验证：没有通过！", nil
	//}

	// 2. DZKP
	proofBytes := zkrow.Columns[org_name].Dzkp.Proof
	proof, err := zksigma.NewDisjunctiveProofFromBytes(proofBytes)
	if err!=nil{
		return "反序列化DZKP失败", nil
	}
	G1 := zksigma.ECPoint{}
	json.Unmarshal(zkrow.Columns[org_name].Dzkp.G1, &G1)
	Y1 := zksigma.ECPoint{}
	json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y1, &Y1)
	G2 := zksigma.ECPoint{}
	json.Unmarshal(zkrow.Columns[org_name].Dzkp.G2, &G2)
	Y2 := zksigma.ECPoint{}
	json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y2, &Y2)
	res2, err := proof.Verify(ZKLedgerCurve, G1, Y1, G2, Y2)

	if res1==false && res2==false{
		return "范围证明、析取证明都不通过！", nil
	} else if res1==false && res2==true {
		return "范围证明不通过！析取证明通过！", nil
	} else if res1==true && res2==false {
		return "范围证明通过！析取证明不通过！", nil
	} else {
		return "范围证明、析取证明全部通过！", nil
	}

	// 3. 验证(Com/Com_{RP})^{sk_{other}}=Token/Token''
	commJsons := zkrow.Columns[org_name].Commitment
	comm := zksigma.ECPoint{}
	err = json.Unmarshal(commJsons, &comm)

	com_rp := zksigma.ECPoint{RP_struct_2.Comm.X, RP_struct_2.Comm.Y}  // 从范围证明中得到Com_{RP}

	tokenJsons := zkrow.Columns[org_name].AuditToken
	token := zksigma.ECPoint{}
	err = json.Unmarshal(tokenJsons, &token)

	tokenDoublePrimeJsons := zkrow.Columns[org_name].TokenDoublePrime
	tokenDoublePrime := zksigma.ECPoint{}
	err = json.Unmarshal(tokenDoublePrimeJsons, &tokenDoublePrime)

	leftSide := zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.Sub(comm, com_rp), sk) //(Com/Com_{RP})^{sk_{other}}
	rightSide := ZKLedgerCurve.Sub(token, tokenDoublePrime) //Token/Token''
	res3 := leftSide.Equal(rightSide)

	// 4. 更新OrgColumn.isValidAsset和zkrow.isValidAsset
	zkrow.Columns[org_name].IsValidAsset = res1 && res2 && res3
	zkrow.IsValidAsset = zkrow.IsValidAsset && zkrow.Columns[org_name].IsValidAsset

	if res1 && res2 && res3==true{
		return "范围证明、析取证明均通过", nil
	}else {
		return "未通过阶段二验证", nil
	}
}

// 由其他组织来调用，完成第二个验证阶段中的范围证明、dzkp、补充证明
func (s *ChaincodeStub)ZkVerifyTwoAll(key string, orgNum int) (string, error) {
	zkrowdata, err := s.GetState(key) // 直接读取[]byte
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
	}
	if zkrowdata == nil {
		return "", fmt.Errorf("Asset not found: %s", key)
	}

	zkrow := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	var res bool
	// 依次验证所有组织的范围证明、dzkp
	for i:=0; i<orgNum; i++ {
		// 组织名
		org_name := "Org" + strconv.Itoa(i+1)
		// 阶段二：验证范围证明和DZKP
		// 1. 范围证明

		// a. JSON反序列化
		//RP_byte_ := zkrow.Columns[org_name].Rp
		//RP_struct_2 := &RangeProof{}
		//err = json.Unmarshal(RP_byte_, RP_struct_2)

		// b. protobuf反序列化
		RP_proto_ := zkrow.Columns[org_name].Rp
		RP_struct_2 := &RangeProof{}
		deserialize_bulletproof(RP_proto_, RP_struct_2)

		res1 := s.Verify_bulletproof(*RP_struct_2)
		//if res1 ==true{
		//	return "范围证明验证通过！", nil
		//}else {
		//	return "范围证明验证：没有通过！", nil
		//}

		// 2. DZKP
		proofBytes := zkrow.Columns[org_name].Dzkp.Proof
		proof, err := zksigma.NewDisjunctiveProofFromBytes(proofBytes)
		if err!=nil{
			return "反序列化DZKP失败", nil
		}
		G1 := zksigma.ECPoint{}
		json.Unmarshal(zkrow.Columns[org_name].Dzkp.G1, &G1)
		Y1 := zksigma.ECPoint{}
		json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y1, &Y1)
		G2 := zksigma.ECPoint{}
		json.Unmarshal(zkrow.Columns[org_name].Dzkp.G2, &G2)
		Y2 := zksigma.ECPoint{}
		json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y2, &Y2)
		res2, err := proof.Verify(ZKLedgerCurve, G1, Y1, G2, Y2)

		// 3. 更新OrgColumn.isValidAsset和zkrow.isValidAsset
		zkrow.Columns[org_name].IsValidAsset = res1 && res2
		//zkrow.IsValidAsset = zkrow.IsValidAsset && zkrow.Columns[org_name].IsValidAsset
		if i==0{
			res = zkrow.Columns[org_name].IsValidAsset
		} else {
			res = res && zkrow.Columns[org_name].IsValidAsset
		}
	}
	zkrow.IsValidAsset = res
	if zkrow.IsValidAsset==true{
		return "范围证明、析取证明全部通过！", nil
	} else {
		return "未通过阶段二验证", nil
	}
}

// ZkVerifyTwoAuditor和ZkVerifyTwoOrg在IsValidAsset的处理上有问题，IsValidAsset实际应为这两个函数验证结果的逻辑与，但将IsValidAsset的赋值分散在两个函数中无法处理了。
// auditor调用，来验证某一组织的范围证明和dzkp
//func (s *ChaincodeStub)ZkVerifyTwoAuditor(key string, orgNum int, org_name string) (string, error) {
//	zkrowdata, err := s.GetState(key) // 直接读取[]byte
//	if err != nil {
//		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
//	}
//	if zkrowdata == nil {
//		return "", fmt.Errorf("Asset not found: %s", key)
//	}
//
//	zkrow := &zkrow_package.Zkrow{}
//	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
//	if err != nil {
//		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
//	}
//
//	// 阶段二：验证范围证明和DZKP
//	// 1. 范围证明
//	RP_byte_ := zkrow.Columns[org_name].Rp
//	RP_struct_2 := &RangeProof{}
//	//t3 := time.Now().UnixNano()/ 1e6
//	err = json.Unmarshal(RP_byte_, RP_struct_2)
//	//t4 := time.Now().UnixNano()/ 1e6
//	res1 := s.Verify_bulletproof(*RP_struct_2)
//
//	//if res1 ==true{
//	//	return "范围证明验证通过！", nil
//	//}else {
//	//	return "范围证明验证：没有通过！", nil
//	//}
//	// 2. DZKP
//	proofBytes := zkrow.Columns[org_name].Dzkp.Proof
//	proof, err := zksigma.NewDisjunctiveProofFromBytes(proofBytes)
//	if err!=nil{
//		return "反序列化DZKP失败", nil
//	}
//	G1 := zksigma.ECPoint{}
//	json.Unmarshal(zkrow.Columns[org_name].Dzkp.G1, &G1)
//	Y1 := zksigma.ECPoint{}
//	json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y1, &Y1)
//	G2 := zksigma.ECPoint{}
//	json.Unmarshal(zkrow.Columns[org_name].Dzkp.G2, &G2)
//	Y2 := zksigma.ECPoint{}
//	json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y2, &Y2)
//	res2, err := proof.Verify(ZKLedgerCurve, G1, Y1, G2, Y2)
//	//fmt.Println("DZKP验证结果：", test)
//	//if res2 ==true{
//	//	return "DZKP验证通过！", nil
//	//}else {
//	//	return "DZKP验证：没有通过！", nil
//	//}
//	// 3. 更新OrgColumn.isValidAsset和zkrow.isValidAsset
//	zkrow.Columns[org_name].IsValidAsset = res1 && res2
//	zkrow.IsValidAsset = zkrow.IsValidAsset && zkrow.Columns[org_name].IsValidAsset
//
//	if res1==false && res2==false{
//		return "范围证明、DZKP都不通过！", nil
//	} else if res1==false && res2==true {
//		return "范围证明不通过！DZKP通过！", nil
//	} else if res1==true && res2==false {
//		return "范围证明通过！DZKP不通过！", nil
//	} else {
//		return "范围证明、DZKP全部通过！", nil
//	}
//}

// 各组织调用，验证自己的范围证明与承诺中的值是否一致
//func (s *ChaincodeStub)ZkVerifyTwoOrg(key string, orgNum int, org_name string, sk *big.Int) (string, error) {
//	zkrowdata, err := s.GetState(key) // 直接读取[]byte
//	if err != nil {
//		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
//	}
//	if zkrowdata == nil {
//		return "", fmt.Errorf("Asset not found: %s", key)
//	}
//
//	zkrow := &zkrow_package.Zkrow{}
//	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
//	if err != nil {
//		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
//	}
//
//	// 0. 获取范围证明
//	RP_byte_ := zkrow.Columns[org_name].Rp
//	RP_struct_2 := &RangeProof{}
//	err = json.Unmarshal(RP_byte_, RP_struct_2)
//
//	// 1. 验证(Com/Com_{RP})^{sk_{other}}=Token/Token''
//	commJsons := zkrow.Columns[org_name].Commitment
//	comm := zksigma.ECPoint{}
//	err = json.Unmarshal(commJsons, &comm)
//
//	com_rp := zksigma.ECPoint{RP_struct_2.Comm.X, RP_struct_2.Comm.Y}  // 从范围证明中得到Com_{RP}
//
//	tokenJsons := zkrow.Columns[org_name].AuditToken
//	token := zksigma.ECPoint{}
//	err = json.Unmarshal(tokenJsons, &token)
//
//	tokenDoublePrimeJsons := zkrow.Columns[org_name].TokenDoublePrime
//	tokenDoublePrime := zksigma.ECPoint{}
//	err = json.Unmarshal(tokenDoublePrimeJsons, &tokenDoublePrime)
//
//	leftSide := zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.Sub(comm, com_rp), sk) //(Com/Com_{RP})^{sk_{other}}
//	rightSide := ZKLedgerCurve.Sub(token, tokenDoublePrime) //Token/Token''
//	res := leftSide.Equal(rightSide)
//
//	// 3. 更新OrgColumn.isValidAsset和zkrow.isValidAsset
//	zkrow.Columns[org_name].IsValidAsset = res
//	zkrow.IsValidAsset = zkrow.IsValidAsset && zkrow.Columns[org_name].IsValidAsset
//
//	if res==true{
//		return "其他组织一致性检查通过！", nil
//	} else {
//		return "其他组织的com_rp与comm中的交易金额不一致！未通过！", nil
//	}
//}

//// 包含了两阶段验证，未实现补充证明
//func (s *ChaincodeStub)ZkVerify(key string, orgNum int, sk *big.Int, org_name string, value *big.Int) (string, error) {
//	zkrowdata, err := s.GetState(key) // 直接读取[]byte
//	if err != nil {
//		return "", fmt.Errorf("Failed to get asset: %s with error: %s", key, err)
//	}
//	if zkrowdata == nil {
//		return "", fmt.Errorf("Asset not found: %s", key)
//	}
//
//	zkrow := &zkrow_package.Zkrow{}
//	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
//	if err != nil {
//		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
//	}
//
//	// 阶段一：验证Proof of Balance和Proof of Correctness
//	// Proof of Balance:
//	commJson := zkrow.Columns["Org1"].Commitment
//	commSum := zksigma.ECPoint{}
//	err = json.Unmarshal(commJson, &commSum)
//	fmt.Println("承诺之和", commSum)
//	for i:=1; i<orgNum; i++{
//		// 读取承诺
//		org_name := "Org" + strconv.Itoa(i+1)
//		commJson := zkrow.Columns[org_name].Commitment
//		comm := zksigma.ECPoint{}
//		err = json.Unmarshal(commJson, &comm)
//		// 求和
//		commSum = ZKLedgerCurve.Add(commSum, comm)
//		fmt.Println("承诺之和", commSum)
//	}
//	fmt.Println("承诺之和", commSum)
//	res1 := commSum.Equal(zksigma.ECPoint{big.NewInt(0), big.NewInt(0)}) // bool
//	fmt.Println("Proof of Balance:", res1)
//
//	// Proof of Correctness:
//	fmt.Println("私钥：", sk)
//	tokenJsons := zkrow.Columns[org_name].AuditToken
//	token := zksigma.ECPoint{}
//	err = json.Unmarshal(tokenJsons, &token)
//	commJson = zkrow.Columns[org_name].Commitment
//	comm := zksigma.ECPoint{}
//	err = json.Unmarshal(commJson, &comm)
//
//	step1 := zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.G, sk) // g^{sk}
//	step2 := zksigma.CommitR(ZKLedgerCurve, step1, value) // g^{sk.u}
//	leftSide := ZKLedgerCurve.Add(token, step2) // token.g^{sk.u}
//	rightSide := zksigma.CommitR(ZKLedgerCurve, comm, sk) // Com^{sk}
//	res2 := leftSide.Equal(rightSide)
//
//	// 阶段二：验证范围证明和DZKP
//	RP_byte_ := zkrow.Columns["Org2"].Rp
//	RP_struct_2 := &RangeProof{}
//	//t3 := time.Now().UnixNano()/ 1e6
//	err = json.Unmarshal(RP_byte_, RP_struct_2)
//	//t4 := time.Now().UnixNano()/ 1e6
//	res := s.Verify_bulletproof(*RP_struct_2)
//
//	//if res ==true{
//	//	return "范围证明验证通过！", nil
//	//}else {
//	//	return "范围证明验证：没有通过！", nil
//	//}
//
//	if (res && res1 && res2) ==true{
//		return "当前所有NIZK通过！", nil
//	}else {
//		return "存在NIZK未通过！", nil
//	}
//}

/*测试API*/
func (s *ChaincodeStub) Cal_commitment(amount string) string {
	amount_int,_:= strconv.Atoi(amount)
	amount_str := strconv.Itoa(amount_int+11)
	//fmt.Println("calculate Pedersen commitment with amount:", amount)
	return amount_str
}

func (s *ChaincodeStub) Cal_auditToken(amount string) {
	fmt.Println("calculate auditToken with amount:", amount)
}


func (s *ChaincodeStub) Test_bulletproof() string {
	gStr := EC.G.X.String()
	return gStr
}


//func serialize_bulletproof(proof RangeProof, rangeProof *zkrow_package.RangeProof)  {
//	commJson, err := json.Marshal(proof.Comm)
//	if err != nil {
//		fmt.Println(err.Error())
//	}
//	rangeProof.Comm = commJson
//
//	IPP_proto := &zkrow_package.InnerProdArg{}
//	// L
//	lJson, err := json.Marshal(proof.IPP.L)
//	if err != nil {
//		fmt.Println(err.Error())
//	}
//	IPP_proto.L = lJson
//	// R
//	rJson, err := json.Marshal(proof.IPP.R)
//	if err != nil {
//		fmt.Println(err.Error())
//	}
//	IPP_proto.R = rJson
//	// A
//	aJson, err := json.Marshal(proof.IPP.A)
//	if err != nil {
//		fmt.Println(err.Error())
//	}
//	IPP_proto.A = aJson
//	// B
//	bJson, err := json.Marshal(proof.IPP.B)
//	if err != nil {
//		fmt.Println(err.Error())
//	}
//	IPP_proto.B = bJson
//	// Challenges
//	for i:=0; i<len(proof.IPP.Challenges); i++{
//		challengeJson, err := json.Marshal(proof.IPP.Challenges[i])
//		if err != nil {
//			fmt.Println(err.Error())
//		}
//		IPP_proto.Challenges = append(IPP_proto.Challenges, challengeJson)
//	}
//	rangeProof.IPP = IPP_proto
//}

func ecpoint_json_marshal(p ECPoint) []byte {
	pJson, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err.Error())
	}
	return pJson
}

func bigint_json_marshal(bigInt *big.Int) []byte {
	bigIntJson, err := json.Marshal(bigInt)
	if err != nil {
		fmt.Println(err.Error())
	}
	return bigIntJson
}

func serialize_bulletproof(proof RangeProof, rangeProof *zkrow_package.RangeProof)  {
	// 1. ECpoint
	// Comm
	rangeProof.Comm = ecpoint_json_marshal(proof.Comm)

	// A
	rangeProof.A = ecpoint_json_marshal(proof.A)

	// S
	rangeProof.S = ecpoint_json_marshal(proof.S)

	// T1
	rangeProof.T1 = ecpoint_json_marshal(proof.T1)

	// T2
	rangeProof.T2 = ecpoint_json_marshal(proof.T2)

	// 2. bigint
	// Tau
	rangeProof.Tau = bigint_json_marshal(proof.Tau)

	// Th
	rangeProof.Th = bigint_json_marshal(proof.Th)

	// Mu
	rangeProof.Mu = bigint_json_marshal(proof.Mu)

	// Cy
	rangeProof.Cy = bigint_json_marshal(proof.Cy)

	// Cz
	rangeProof.Cz = bigint_json_marshal(proof.Cz)

	// Cx
	rangeProof.Cx = bigint_json_marshal(proof.Cx)

	// 3. IPP
	IPP_proto := &zkrow_package.InnerProdArg{}
	// L
	lJson, err := json.Marshal(proof.IPP.L)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.L = lJson
	// R
	rJson, err := json.Marshal(proof.IPP.R)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.R = rJson
	// A
	aBigintJson, err := json.Marshal(proof.IPP.A)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.A = aBigintJson
	// B
	bJson, err := json.Marshal(proof.IPP.B)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.B = bJson
	// Challenges
	for i:=0; i<len(proof.IPP.Challenges); i++{
		challengeJson, err := json.Marshal(proof.IPP.Challenges[i])
		if err != nil {
			fmt.Println(err.Error())
		}
		IPP_proto.Challenges = append(IPP_proto.Challenges, challengeJson)
	}
	rangeProof.IPP = IPP_proto

}

func ecpoint_json_unmarshal(b []byte) ECPoint {
	p := &ECPoint{}
	err := json.Unmarshal(b, p)
	if err != nil {
		fmt.Println(err.Error())
	}
	return *p
}

func bigint_json_unmarshal(b []byte) *big.Int{
	bigint := &big.Int{}
	err := json.Unmarshal(b, bigint)
	if err != nil {
		fmt.Println(err.Error())
	}
	return bigint
}

func deserialize_bulletproof(rangeProof *zkrow_package.RangeProof, proof *RangeProof)  {
	// 1. ECpoint
	// Comm
	proof.Comm = ecpoint_json_unmarshal(rangeProof.Comm)

	// A
	proof.A = ecpoint_json_unmarshal(rangeProof.A)

	// S
	proof.S = ecpoint_json_unmarshal(rangeProof.S)

	// T1
	proof.T1 = ecpoint_json_unmarshal(rangeProof.T1)

	// T2
	proof.T2 = ecpoint_json_unmarshal(rangeProof.T2)

	// 2. bigint
	// Tau
	proof.Tau = bigint_json_unmarshal(rangeProof.Tau)

	// Th
	proof.Th = bigint_json_unmarshal(rangeProof.Th)

	// Mu
	proof.Mu = bigint_json_unmarshal(rangeProof.Mu)

	// Cy
	proof.Cy = bigint_json_unmarshal(rangeProof.Cy)

	// Cz
	proof.Cz = bigint_json_unmarshal(rangeProof.Cz)

	// Cx
	proof.Cx = bigint_json_unmarshal(rangeProof.Cx)

	// 3. IPP
	IPP_struct := InnerProdArg{}
	// L
	L := &[]ECPoint{}
	err := json.Unmarshal(rangeProof.IPP.L, L)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.L = *L
	// R
	R := &[]ECPoint{}
	err = json.Unmarshal(rangeProof.IPP.R, R)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.R = *R
	// A
	A := &big.Int{}
	err = json.Unmarshal(rangeProof.IPP.A, A)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.A = A
	// B
	B := &big.Int{}
	err = json.Unmarshal(rangeProof.IPP.B, B)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.B = B
	// Challenges
	for i:=0; i<len(rangeProof.IPP.Challenges); i++{
		tmp := &big.Int{}
		err = json.Unmarshal(rangeProof.IPP.Challenges[i], tmp)
		if err != nil {
			fmt.Println(err.Error())
		}
		IPP_struct.Challenges = append(IPP_struct.Challenges, tmp)
	}
	proof.IPP = IPP_struct
}

// GetTxID returns the transaction ID for the proposal
func (s *ChaincodeStub) GetTxID() string {
	return s.TxID
}

// GetChannelID returns the channel for the proposal
func (s *ChaincodeStub) GetChannelID() string {
	return s.ChannelID
}

// GetDecorations ...
func (s *ChaincodeStub) GetDecorations() map[string][]byte {
	return s.decorations
}

// GetMSPID returns the local mspid of the peer by checking the CORE_PEER_LOCALMSPID
// env var and returns an error if the env var is not set
func GetMSPID() (string, error) {
	mspid := os.Getenv("CORE_PEER_LOCALMSPID")

	if mspid == "" {
		return "", errors.New("'CORE_PEER_LOCALMSPID' is not set")
	}

	return mspid, nil
}

// ------------- Call Chaincode functions ---------------

// InvokeChaincode documentation can be found in interfaces.go
func (s *ChaincodeStub) InvokeChaincode(chaincodeName string, args [][]byte, channel string) pb.Response {
	// Internally we handle chaincode name as a composite name
	if channel != "" {
		chaincodeName = chaincodeName + "/" + channel
	}
	return s.handler.handleInvokeChaincode(chaincodeName, args, s.ChannelID, s.TxID)
}

// --------- State functions ----------

// GetState documentation can be found in interfaces.go
func (s *ChaincodeStub) GetState(key string) ([]byte, error) {
	// Access public data by setting the collection to empty string
	collection := ""
	return s.handler.handleGetState(collection, key, s.ChannelID, s.TxID)
}

// SetStateValidationParameter documentation can be found in interfaces.go
func (s *ChaincodeStub) SetStateValidationParameter(key string, ep []byte) error {
	return s.handler.handlePutStateMetadataEntry("", key, s.validationParameterMetakey, ep, s.ChannelID, s.TxID)
}

// GetStateValidationParameter documentation can be found in interfaces.go
func (s *ChaincodeStub) GetStateValidationParameter(key string) ([]byte, error) {
	md, err := s.handler.handleGetStateMetadata("", key, s.ChannelID, s.TxID)
	if err != nil {
		return nil, err
	}
	if ep, ok := md[s.validationParameterMetakey]; ok {
		return ep, nil
	}
	return nil, nil
}

// PutState documentation can be found in interfaces.go
func (s *ChaincodeStub) PutState(key string, value []byte) error {
	if key == "" {
		return errors.New("key must not be an empty string")
	}
	// Access public data by setting the collection to empty string
	collection := ""
	return s.handler.handlePutState(collection, key, value, s.ChannelID, s.TxID)
}

func (s *ChaincodeStub) createStateQueryIterator(response *pb.QueryResponse) *StateQueryIterator {
	return &StateQueryIterator{
		CommonIterator: &CommonIterator{
			handler:    s.handler,
			channelID:  s.ChannelID,
			txid:       s.TxID,
			response:   response,
			currentLoc: 0,
		},
	}
}

// GetQueryResult documentation can be found in interfaces.go
func (s *ChaincodeStub) GetQueryResult(query string) (StateQueryIteratorInterface, error) {
	// Access public data by setting the collection to empty string
	collection := ""
	// ignore QueryResponseMetadata as it is not applicable for a rich query without pagination
	iterator, _, err := s.handleGetQueryResult(collection, query, nil)

	return iterator, err
}

// DelState documentation can be found in interfaces.go
func (s *ChaincodeStub) DelState(key string) error {
	// Access public data by setting the collection to empty string
	collection := ""
	return s.handler.handleDelState(collection, key, s.ChannelID, s.TxID)
}

//  ---------  private state functions  ---------

// GetPrivateData documentation can be found in interfaces.go
func (s *ChaincodeStub) GetPrivateData(collection string, key string) ([]byte, error) {
	if collection == "" {
		return nil, fmt.Errorf("collection must not be an empty string")
	}
	return s.handler.handleGetState(collection, key, s.ChannelID, s.TxID)
}

// GetPrivateDataHash documentation can be found in interfaces.go
func (s *ChaincodeStub) GetPrivateDataHash(collection string, key string) ([]byte, error) {
	if collection == "" {
		return nil, fmt.Errorf("collection must not be an empty string")
	}
	return s.handler.handleGetPrivateDataHash(collection, key, s.ChannelID, s.TxID)
}

// PutPrivateData documentation can be found in interfaces.go
func (s *ChaincodeStub) PutPrivateData(collection string, key string, value []byte) error {
	if collection == "" {
		return fmt.Errorf("collection must not be an empty string")
	}
	if key == "" {
		return fmt.Errorf("key must not be an empty string")
	}
	return s.handler.handlePutState(collection, key, value, s.ChannelID, s.TxID)
}

// DelPrivateData documentation can be found in interfaces.go
func (s *ChaincodeStub) DelPrivateData(collection string, key string) error {
	if collection == "" {
		return fmt.Errorf("collection must not be an empty string")
	}
	return s.handler.handleDelState(collection, key, s.ChannelID, s.TxID)
}

// GetPrivateDataByRange documentation can be found in interfaces.go
func (s *ChaincodeStub) GetPrivateDataByRange(collection, startKey, endKey string) (StateQueryIteratorInterface, error) {
	if collection == "" {
		return nil, fmt.Errorf("collection must not be an empty string")
	}
	if startKey == "" {
		startKey = emptyKeySubstitute
	}
	if err := validateSimpleKeys(startKey, endKey); err != nil {
		return nil, err
	}
	// ignore QueryResponseMetadata as it is not applicable for a range query without pagination
	iterator, _, err := s.handleGetStateByRange(collection, startKey, endKey, nil)

	return iterator, err
}

func (s *ChaincodeStub) createRangeKeysForPartialCompositeKey(objectType string, attributes []string) (string, string, error) {
	partialCompositeKey, err := s.CreateCompositeKey(objectType, attributes)
	if err != nil {
		return "", "", err
	}
	startKey := partialCompositeKey
	endKey := partialCompositeKey + string(maxUnicodeRuneValue)

	return startKey, endKey, nil
}

// GetPrivateDataByPartialCompositeKey documentation can be found in interfaces.go
func (s *ChaincodeStub) GetPrivateDataByPartialCompositeKey(collection, objectType string, attributes []string) (StateQueryIteratorInterface, error) {
	if collection == "" {
		return nil, fmt.Errorf("collection must not be an empty string")
	}

	startKey, endKey, err := s.createRangeKeysForPartialCompositeKey(objectType, attributes)
	if err != nil {
		return nil, err
	}
	// ignore QueryResponseMetadata as it is not applicable for a partial composite key query without pagination
	iterator, _, err := s.handleGetStateByRange(collection, startKey, endKey, nil)

	return iterator, err
}

// GetPrivateDataQueryResult documentation can be found in interfaces.go
func (s *ChaincodeStub) GetPrivateDataQueryResult(collection, query string) (StateQueryIteratorInterface, error) {
	if collection == "" {
		return nil, fmt.Errorf("collection must not be an empty string")
	}
	// ignore QueryResponseMetadata as it is not applicable for a range query without pagination
	iterator, _, err := s.handleGetQueryResult(collection, query, nil)

	return iterator, err
}

// GetPrivateDataValidationParameter documentation can be found in interfaces.go
func (s *ChaincodeStub) GetPrivateDataValidationParameter(collection, key string) ([]byte, error) {
	md, err := s.handler.handleGetStateMetadata(collection, key, s.ChannelID, s.TxID)
	if err != nil {
		return nil, err
	}
	if ep, ok := md[s.validationParameterMetakey]; ok {
		return ep, nil
	}
	return nil, nil
}

// SetPrivateDataValidationParameter documentation can be found in interfaces.go
func (s *ChaincodeStub) SetPrivateDataValidationParameter(collection, key string, ep []byte) error {
	return s.handler.handlePutStateMetadataEntry(collection, key, s.validationParameterMetakey, ep, s.ChannelID, s.TxID)
}

// CommonIterator documentation can be found in interfaces.go
type CommonIterator struct {
	handler    *Handler
	channelID  string
	txid       string
	response   *pb.QueryResponse
	currentLoc int
}

// StateQueryIterator documentation can be found in interfaces.go
type StateQueryIterator struct {
	*CommonIterator
}

// HistoryQueryIterator documentation can be found in interfaces.go
type HistoryQueryIterator struct {
	*CommonIterator
}

// General interface for supporting different types of query results.
// Actual types differ for different queries
type queryResult interface{}

type resultType uint8

// TODO: Document constants
/*
	Constants ...
*/
const (
	StateQueryResult resultType = iota + 1
	HistoryQueryResult
)

func createQueryResponseMetadata(metadataBytes []byte) (*pb.QueryResponseMetadata, error) {
	metadata := &pb.QueryResponseMetadata{}
	err := proto.Unmarshal(metadataBytes, metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

func (s *ChaincodeStub) handleGetStateByRange(collection, startKey, endKey string,
	metadata []byte) (StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {

	response, err := s.handler.handleGetStateByRange(collection, startKey, endKey, metadata, s.ChannelID, s.TxID)
	if err != nil {
		return nil, nil, err
	}

	iterator := s.createStateQueryIterator(response)
	responseMetadata, err := createQueryResponseMetadata(response.Metadata)
	if err != nil {
		return nil, nil, err
	}

	return iterator, responseMetadata, nil
}

func (s *ChaincodeStub) handleGetQueryResult(collection, query string,
	metadata []byte) (StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {

	response, err := s.handler.handleGetQueryResult(collection, query, metadata, s.ChannelID, s.TxID)
	if err != nil {
		return nil, nil, err
	}

	iterator := s.createStateQueryIterator(response)
	responseMetadata, err := createQueryResponseMetadata(response.Metadata)
	if err != nil {
		return nil, nil, err
	}

	return iterator, responseMetadata, nil
}

// GetStateByRange documentation can be found in interfaces.go
func (s *ChaincodeStub) GetStateByRange(startKey, endKey string) (StateQueryIteratorInterface, error) {
	if startKey == "" {
		startKey = emptyKeySubstitute
	}
	if err := validateSimpleKeys(startKey, endKey); err != nil {
		return nil, err
	}
	collection := ""

	// ignore QueryResponseMetadata as it is not applicable for a range query without pagination
	iterator, _, err := s.handleGetStateByRange(collection, startKey, endKey, nil)

	return iterator, err
}

// GetHistoryForKey documentation can be found in interfaces.go
func (s *ChaincodeStub) GetHistoryForKey(key string) (HistoryQueryIteratorInterface, error) {
	response, err := s.handler.handleGetHistoryForKey(key, s.ChannelID, s.TxID)
	if err != nil {
		return nil, err
	}
	return &HistoryQueryIterator{CommonIterator: &CommonIterator{s.handler, s.ChannelID, s.TxID, response, 0}}, nil
}

//CreateCompositeKey documentation can be found in interfaces.go
func (s *ChaincodeStub) CreateCompositeKey(objectType string, attributes []string) (string, error) {
	return CreateCompositeKey(objectType, attributes)
}

//SplitCompositeKey documentation can be found in interfaces.go
func (s *ChaincodeStub) SplitCompositeKey(compositeKey string) (string, []string, error) {
	return splitCompositeKey(compositeKey)
}

// CreateCompositeKey ...
func CreateCompositeKey(objectType string, attributes []string) (string, error) {
	if err := validateCompositeKeyAttribute(objectType); err != nil {
		return "", err
	}
	ck := compositeKeyNamespace + objectType + string(minUnicodeRuneValue)
	for _, att := range attributes {
		if err := validateCompositeKeyAttribute(att); err != nil {
			return "", err
		}
		ck += att + string(minUnicodeRuneValue)
	}
	return ck, nil
}

func splitCompositeKey(compositeKey string) (string, []string, error) {
	componentIndex := 1
	components := []string{}
	for i := 1; i < len(compositeKey); i++ {
		if compositeKey[i] == minUnicodeRuneValue {
			components = append(components, compositeKey[componentIndex:i])
			componentIndex = i + 1
		}
	}
	return components[0], components[1:], nil
}

func validateCompositeKeyAttribute(str string) error {
	if !utf8.ValidString(str) {
		return fmt.Errorf("not a valid utf8 string: [%x]", str)
	}
	for index, runeValue := range str {
		if runeValue == minUnicodeRuneValue || runeValue == maxUnicodeRuneValue {
			return fmt.Errorf(`input contains unicode %#U starting at position [%d]. %#U and %#U are not allowed in the input attribute of a composite key`,
				runeValue, index, minUnicodeRuneValue, maxUnicodeRuneValue)
		}
	}
	return nil
}

//To ensure that simple keys do not go into composite key namespace,
//we validate simplekey to check whether the key starts with 0x00 (which
//is the namespace for compositeKey). This helps in avoding simple/composite
//key collisions.
func validateSimpleKeys(simpleKeys ...string) error {
	for _, key := range simpleKeys {
		if len(key) > 0 && key[0] == compositeKeyNamespace[0] {
			return fmt.Errorf(`first character of the key [%s] contains a null character which is not allowed`, key)
		}
	}
	return nil
}

//GetStateByPartialCompositeKey function can be invoked by a chaincode to query the
//state based on a given partial composite key. This function returns an
//iterator which can be used to iterate over all composite keys whose prefix
//matches the given partial composite key. This function should be used only for
//a partial composite key. For a full composite key, an iter with empty response
//would be returned.
func (s *ChaincodeStub) GetStateByPartialCompositeKey(objectType string, attributes []string) (StateQueryIteratorInterface, error) {
	collection := ""
	startKey, endKey, err := s.createRangeKeysForPartialCompositeKey(objectType, attributes)
	if err != nil {
		return nil, err
	}
	// ignore QueryResponseMetadata as it is not applicable for a partial composite key query without pagination
	iterator, _, err := s.handleGetStateByRange(collection, startKey, endKey, nil)

	return iterator, err
}

func createQueryMetadata(pageSize int32, bookmark string) ([]byte, error) {
	// Construct the QueryMetadata with a page size and a bookmark needed for pagination
	metadata := &pb.QueryMetadata{PageSize: pageSize, Bookmark: bookmark}
	metadataBytes, err := proto.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	return metadataBytes, nil
}

// GetStateByRangeWithPagination ...
func (s *ChaincodeStub) GetStateByRangeWithPagination(startKey, endKey string, pageSize int32,
	bookmark string) (StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {

	if startKey == "" {
		startKey = emptyKeySubstitute
	}
	if err := validateSimpleKeys(startKey, endKey); err != nil {
		return nil, nil, err
	}

	collection := ""

	metadata, err := createQueryMetadata(pageSize, bookmark)
	if err != nil {
		return nil, nil, err
	}

	return s.handleGetStateByRange(collection, startKey, endKey, metadata)
}

// GetStateByPartialCompositeKeyWithPagination ...
func (s *ChaincodeStub) GetStateByPartialCompositeKeyWithPagination(objectType string, keys []string,
	pageSize int32, bookmark string) (StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {

	collection := ""

	metadata, err := createQueryMetadata(pageSize, bookmark)
	if err != nil {
		return nil, nil, err
	}

	startKey, endKey, err := s.createRangeKeysForPartialCompositeKey(objectType, keys)
	if err != nil {
		return nil, nil, err
	}
	return s.handleGetStateByRange(collection, startKey, endKey, metadata)
}

// GetQueryResultWithPagination ...
func (s *ChaincodeStub) GetQueryResultWithPagination(query string, pageSize int32,
	bookmark string) (StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	// Access public data by setting the collection to empty string
	collection := ""

	metadata, err := createQueryMetadata(pageSize, bookmark)
	if err != nil {
		return nil, nil, err
	}
	return s.handleGetQueryResult(collection, query, metadata)
}

// Next ...
func (iter *StateQueryIterator) Next() (*queryresult.KV, error) {
	result, err := iter.nextResult(StateQueryResult)
	if err != nil {
		return nil, err
	}
	return result.(*queryresult.KV), err
}

// Next ...
func (iter *HistoryQueryIterator) Next() (*queryresult.KeyModification, error) {
	result, err := iter.nextResult(HistoryQueryResult)
	if err != nil {
		return nil, err
	}
	return result.(*queryresult.KeyModification), err
}

// HasNext documentation can be found in interfaces.go
func (iter *CommonIterator) HasNext() bool {
	if iter.currentLoc < len(iter.response.Results) || iter.response.HasMore {
		return true
	}
	return false
}

// getResultsFromBytes deserializes QueryResult and return either a KV struct
// or KeyModification depending on the result type (i.e., state (range/execute)
// query, history query). Note that queryResult is an empty golang
// interface that can hold values of any type.
func (iter *CommonIterator) getResultFromBytes(queryResultBytes *pb.QueryResultBytes,
	rType resultType) (queryResult, error) {

	if rType == StateQueryResult {
		stateQueryResult := &queryresult.KV{}
		if err := proto.Unmarshal(queryResultBytes.ResultBytes, stateQueryResult); err != nil {
			return nil, fmt.Errorf("error unmarshaling result from bytes: %s", err)
		}
		return stateQueryResult, nil

	} else if rType == HistoryQueryResult {
		historyQueryResult := &queryresult.KeyModification{}
		if err := proto.Unmarshal(queryResultBytes.ResultBytes, historyQueryResult); err != nil {
			return nil, err
		}
		return historyQueryResult, nil
	}
	return nil, errors.New("wrong result type")
}

func (iter *CommonIterator) fetchNextQueryResult() error {
	response, err := iter.handler.handleQueryStateNext(iter.response.Id, iter.channelID, iter.txid)
	if err != nil {
		return err
	}
	iter.currentLoc = 0
	iter.response = response
	return nil
}

// nextResult returns the next QueryResult (i.e., either a KV struct or KeyModification)
// from the state or history query iterator. Note that queryResult is an
// empty golang interface that can hold values of any type.
func (iter *CommonIterator) nextResult(rType resultType) (queryResult, error) {
	if iter.currentLoc < len(iter.response.Results) {
		// On valid access of an element from cached results
		queryResult, err := iter.getResultFromBytes(iter.response.Results[iter.currentLoc], rType)
		if err != nil {
			return nil, err
		}
		iter.currentLoc++

		if iter.currentLoc == len(iter.response.Results) && iter.response.HasMore {
			// On access of last item, pre-fetch to update HasMore flag
			if err = iter.fetchNextQueryResult(); err != nil {
				return nil, err
			}
		}

		return queryResult, err
	} else if !iter.response.HasMore {
		// On call to Next() without check of HasMore
		return nil, errors.New("no such key")
	}

	// should not fall through here
	// case: no cached results but HasMore is true.
	return nil, errors.New("invalid iterator state")
}

// Close documentation can be found in interfaces.go
func (iter *CommonIterator) Close() error {
	_, err := iter.handler.handleQueryStateClose(iter.response.Id, iter.channelID, iter.txid)
	return err
}

// GetArgs documentation can be found in interfaces.go
func (s *ChaincodeStub) GetArgs() [][]byte {
	return s.args
}

// GetStringArgs documentation can be found in interfaces.go
func (s *ChaincodeStub) GetStringArgs() []string {
	args := s.GetArgs()
	strargs := make([]string, 0, len(args))
	for _, barg := range args {
		strargs = append(strargs, string(barg))
	}
	return strargs
}

// GetFunctionAndParameters documentation can be found in interfaces.go
func (s *ChaincodeStub) GetFunctionAndParameters() (function string, params []string) {
	allargs := s.GetStringArgs()
	function = ""
	params = []string{}
	if len(allargs) >= 1 {
		function = allargs[0]
		params = allargs[1:]
	}
	return
}

// GetCreator documentation can be found in interfaces.go
func (s *ChaincodeStub) GetCreator() ([]byte, error) {
	return s.creator, nil
}

// GetTransient documentation can be found in interfaces.go
func (s *ChaincodeStub) GetTransient() (map[string][]byte, error) {
	return s.transient, nil
}

// GetBinding documentation can be found in interfaces.go
func (s *ChaincodeStub) GetBinding() ([]byte, error) {
	return s.binding, nil
}

// GetSignedProposal documentation can be found in interfaces.go
func (s *ChaincodeStub) GetSignedProposal() (*pb.SignedProposal, error) {
	return s.signedProposal, nil
}

// GetArgsSlice documentation can be found in interfaces.go
func (s *ChaincodeStub) GetArgsSlice() ([]byte, error) {
	args := s.GetArgs()
	res := []byte{}
	for _, barg := range args {
		res = append(res, barg...)
	}
	return res, nil
}

// GetTxTimestamp documentation can be found in interfaces.go
func (s *ChaincodeStub) GetTxTimestamp() (*timestamp.Timestamp, error) {
	hdr := &common.Header{}
	if err := proto.Unmarshal(s.proposal.Header, hdr); err != nil {
		return nil, fmt.Errorf("error unmarshaling Header: %s", err)
	}

	chdr := &common.ChannelHeader{}
	if err := proto.Unmarshal(hdr.ChannelHeader, chdr); err != nil {
		return nil, fmt.Errorf("error unmarshaling ChannelHeader: %s", err)
	}

	return chdr.GetTimestamp(), nil
}

// ------------- ChaincodeEvent API ----------------------

// SetEvent documentation can be found in interfaces.go
func (s *ChaincodeStub) SetEvent(name string, payload []byte) error {
	if name == "" {
		return errors.New("event name can not be empty string")
	}
	s.chaincodeEvent = &pb.ChaincodeEvent{EventName: name, Payload: payload}
	return nil
}
