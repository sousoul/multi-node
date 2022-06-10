package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"

	"chaincode/protobuf"
	"github.com/golang/protobuf/proto"

	"crypto/sha256"
	"encoding/hex"

	"github.com/mit-dci/zksigma"
)

// SimpleAsset implements a simple chaincode to manage an asset
type SimpleAsset struct {
}

type Transaction struct {
	ID    		string 		`json:"id"` // transaction identifier
	Zkrow		string		`json:"zkrow"`
}

//type TxSpecification struct {
//	Pk []zksigma.ECPoint
//	R []*big.Int
//	Value []*big.Int
//}

// Init is called during chaincode instantiation to initialize any
// data. Note that chaincode upgrade also calls this function to reset
// or to migrate data.
func (t *SimpleAsset) Init(stub shim.ChaincodeStubInterface,) peer.Response {
	fmt.Printf("init...")
	// When an application chaincode is instantiated on a chan- nel, its init function initializes the tabular structure of the public ledger for each organization.
	// Values such as organization name (or ID), public key and initial asset amount can be loaded from the channel’s genesis block.
	// 大概看了下configtx.yaml中有organization name(ID)，公钥就是证书吗？
	// The init function calls the ZKPutState API to create the first row on the public ledger.

	//txSpeJsons := args[0]
	//txSpeStruct := TxSpecification{}
	//json.Unmarshal([]byte(txSpeJsons), &txSpeStruct)
	//fmt.Println("结构体", txSpeStruct)

	// 调用ZkPutState，计算<Com, Token>，并在账本上添加一笔新的交易
	//fmt.Println("调用ZkPutState_test")
	//res, err := stub.ZkPutState_test(txSpeJsons) // 测试

	// 定义账本中的一行，这里是以结构体指针的形式定义的

	first_row := &zkrow_package.Zkrow {
		Columns: map[string]*zkrow_package.OrgColumn{},
		IsValidAsset: false,
		IsValidBalCor: false,
	}
	// 计算承诺、token
	comm := zksigma.ECPoint{big.NewInt(1), big.NewInt(2)}
	token := zksigma.ECPoint{big.NewInt(3), big.NewInt(4)}

	// 序列化
	commJsons, err := json.Marshal(comm) // []byte
	if err != nil {
		fmt.Println(err.Error())
	}
	tokenJsons, err := json.Marshal(token) // []byte
	if err != nil {
		fmt.Println(err.Error())
	}
	// 定义一个组织的信息
	org_name := "Apple" // 定义一个组织名
	org_info := &zkrow_package.OrgColumn{
		Commitment: commJsons,
		AuditToken: tokenJsons,
		IsValidBalCor: false,
		IsValidAsset: false,
	}
	// 将组织信息添加到账本中的一行
	first_row.Columns[org_name] = org_info
	first_row.Columns["Org2"] = org_info

	zkrowdata, err := proto.Marshal(first_row) // protobuf序列化
	if err != nil {
		return shim.Error("初始化二维账本失败")
	}

	err = stub.PutState("二维账本第一行", zkrowdata)
	if err != nil {
		return shim.Error("初始化二维账本失败")
	}

	return shim.Success(nil)
}

// Invoke is called per transaction on the chaincode. Each transaction is
// either a 'get' or a 'set' on the asset created by Init function. The Set
// method may create a new asset by specifying a new key-value pair.
func (t *SimpleAsset) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// Extract the function and args from the transaction proposal
	fn, args := stub.GetFunctionAndParameters()

	var result string
	var err error
	if fn == "set" {
		result, err = set(stub, args)
	}  else if fn == "get"{
		result, err = get(stub, args)
	} else if fn == "comm"{
		result, err = comm(stub, args)
	} else if fn == "initLedger"{
		result, err = initLedger(stub, args)
	} else if fn == "read_from_ledger"{
		result, err = read_from_ledger(stub, args)
	} else if fn == "lock"{
		result, err = lock(stub, args)
	} else if fn == "withdraw"{
		result, err = withdraw(stub, args)
	} else if fn == "test_invoke"{
		result, err = test_invoke(stub)
	} else if fn == "chaincode_invoke"{
		result, err = chaincode_invoke(stub)
	} else if fn=="token"{
		result, err = token(stub, args)
	} else if fn=="transfer"{
		result, err = transfer(stub, args)
	} else if fn=="validation"{
		result, err = validation(stub, args)
	} else if fn=="validationStep1"{
		result, err = validationStep1(stub, args)
	} else if fn=="validationStep2"{
		result, err = validationStep2(stub, args)
	} else if fn=="validationStep2All"{
		result, err = validationStep2All(stub, args)
	} else if fn=="audit"{
		result, err = audit(stub, args)
	} else if fn=="testsize"{
		result, err = testsize(stub, args)
	} else{
		return shim.Error("调用的函数名错误")
	}
	if err != nil {
		return shim.Error(err.Error())
	}

	// Return the result as success payload
	return shim.Success([]byte(result))
}

// 测试不同的组织调用链码，在容器中查看输出
func test_invoke(stub shim.ChaincodeStubInterface) (string, error) {
	//for i:=0;i<100;i++{
	//	fmt.Printf("7777777777")
	//}
	log.Println("8888888888888888888888888888888888888")
	return "success",nil
}

// 链码调用接口，用来调用shim中编写的密码学原语API并测试
//func chaincode_invoke(stub shim.ChaincodeStubInterface, args []string) (string, error) {
//	res := stub.Test_bulletproof()
//	return res,nil
//}

// 测试Pedersen承诺计算
func chaincode_invoke(stub shim.ChaincodeStubInterface) (string, error) {
	args := stub.GetStringArgs() // 获取string数组参数，既可[]string传入，也可用shim中的API获取
	valueStr := args[1] // 注意此时args[0]是function name
	rStr := args[2]

	//value, _ := strconv.Atoi(valueStr)
	//r, _ := strconv.Atoi(rStr)
	value, err := strconv.ParseInt(valueStr, 10, 64) // string to int64
	if err == nil {
		fmt.Printf("%d of type %T", value, value)
	}
	r, err := strconv.ParseInt(rStr, 10, 64) // string to int64
	if err == nil {
		fmt.Printf("%d of type %T", r, r)
	}

	res := stub.Commitment(big.NewInt(value), big.NewInt(r))
	//
	return res.X.String(),nil
	//return valueStr, nil
}

func string2int64(s string) int64 {
	s_int, err := strconv.ParseInt(s, 10, 64) // string to int64
	if err == nil {
		fmt.Printf("%d of type %T", s_int, s_int)
	}
	return s_int
}

type ECPoint struct {
	X, Y *big.Int
}

//// 测试Token计算
func token(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	pkStr := args[0]
	rStr := args[1]
	r := string2int64(rStr)

	pk := zksigma.ECPoint{}
	json.Unmarshal([]byte(pkStr), &pk)

	//pk := ECPoint{big.NewInt(1), big.NewInt(2)}
	//pk, err := strconv.ParseInt(pkStr, 10, 64) // string to int64
	//if err == nil {
	//	fmt.Printf("%d of type %T", pk, pk)
	//}
	//r, err := strconv.ParseInt(rStr, 10, 64) // string to int64
	//if err == nil {
	//	fmt.Printf("%d of type %T", r, r)
	//}

	res := stub.Token(pk, big.NewInt(r))
	return res.X.String(),nil
}

// 初始化二维账本
func initLedger(stub shim.ChaincodeStubInterface, args []string) (string, error){
	txSpeJsons := args[0]
	//txSpeStruct := TxSpecification{}
	//json.Unmarshal([]byte(txSpeJsons), &txSpeStruct)
	fmt.Println("结构体", string(txSpeJsons))

	// 调用ZkPutState，计算<Com, Token>，并在账本上添加一笔新的交易
	//fmt.Println("调用ZkPutState_test")
	key := args[1]
	res, err := stub.ZkPutState_test(txSpeJsons, key) // 测试
	if err != nil {
		return "初始化二维账本失败", fmt.Errorf("")
	}
	fmt.Println(res)

	return "成功初始化二维账本", nil
}

// 从二维账本中读取，主要添加反序列化的代码
func read_from_ledger(stub shim.ChaincodeStubInterface, args []string) (string, error)  {
	if len(args) != 1 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key")
	}
	value, err := stub.GetState(args[0])
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", args[0], err)
	}
	if value == nil {
		return "", fmt.Errorf("Asset not found: %s", args[0])
	}

	zkrowdata := value // 直接读取[]byte

	zkrow := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	log.Println("让我看看docker日志中有没有呢！！！！！！！！！！！！！！")
	//log.Println("测试范围证明", string(zkrow.Columns["Apple"].Rp.))
	//return strconv.FormatBool(zkrow.IsValidBalCor), nil
	//return string(zkrow.Columns["Apple"].Commitment), nil
	return string(zkrow.Columns["Org2"].Commitment), nil // 当组织名字不存在时，报错： Multiple errors occurred: - Transaction processing for endorser [peer1.org2.example.com:10051]: Chaincode status Code: (500) UNKNOWN. Description: error in simulation: failed to execute transaction 60e3e0c44c54c8be3bcc5733903044f03f67425dd74d015c6cbfd77bdb2479b9: error sending: chaincode stream terminated - Transaction processing for endorser [peer1.org1.example.com:9051]: Chaincode status Code: (500) UNKNOWN. Description: error in simulation: failed to execute transaction 60e3e0c44c54c8be3bcc5733903044f03f67425dd74d015c6cbfd77bdb2479b9: error sending: chaincode stream terminated
}

// 从二维账本中读取一行，测试各部分的空间开销
func testsize(stub shim.ChaincodeStubInterface, args []string) (string, error)  {
	key := args[0]
	if len(args) != 1 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key")
	}
	zkrowdata, err := stub.GetState(key) // 读取
	if err != nil {
		return "Failed to get asset", fmt.Errorf("Failed to get asset: %s with error: %s", args[0], err)
	}
	if zkrowdata == nil {
		return "Asset not found", fmt.Errorf("Asset not found: %s", args[0])
	}

	zkrow := &zkrow_package.Zkrow{}
	err = proto.Unmarshal(zkrowdata, zkrow) // protobuf反序列化，[]byte转为结构体
	if err != nil {
		return "", fmt.Errorf("Protobuf Unmarshaling error: ", err)
	}

	// Rp是JSON序列化后的[]byte
	//res := fmt.Sprintf("zkrow序列化后：%dB\n" +
	//	"zkrow序列化前: %dB\n" +
	//	"OrgColumn: %dB\n" +
	//	" Com: %dB\n" +
	//	" Token: %dB\n" +
	//	" IsValidBalCor: %dB\n" +
	//	" isValidAsset: %dB\n" +
	//	" Token': %dB\n" +
	//	" Token'': %dB\n" +
	//	" rp: %dB\n" +
	//	" sizeof(dzkp): %dB\n" +
	//	" dzkp.proof: %dB\n" +
	//	" dzkp.G1: %dB\n" +
	//	" dzkp.Y1: %dB\n" +
	//	" dzkp.G2: %dB\n" +
	//	" dzkp.Y2: %dB\n" +
	//	" S: %dB\n" +
	//	" T: %dB\n", len(zkrowdata), unsafe.Sizeof(*zkrow), unsafe.Sizeof(*(zkrow.Columns["Org1"])),
	//	len(zkrow.Columns["Org1"].Commitment), len(zkrow.Columns["Org1"].AuditToken),
	//	unsafe.Sizeof(zkrow.Columns["Org1"].IsValidBalCor), unsafe.Sizeof(zkrow.Columns["Org1"].IsValidAsset),
	//	len(zkrow.Columns["Org1"].TokenPrime), len(zkrow.Columns["Org1"].TokenDoublePrime),
	//	len(zkrow.Columns["Org1"].Rp), unsafe.Sizeof(*(zkrow.Columns["Org1"].Dzkp)),
	//	len(zkrow.Columns["Org1"].Dzkp.Proof), len(zkrow.Columns["Org1"].Dzkp.G1),
	//	len(zkrow.Columns["Org1"].Dzkp.Y1), len(zkrow.Columns["Org1"].Dzkp.G2),
	//	len(zkrow.Columns["Org1"].Dzkp.Y2),
	//	len(zkrow.Columns["Org1"].S), len(zkrow.Columns["Org1"].T),)

	res := fmt.Sprintf("zkrow序列化后：%dB\n" +
		"zkrow序列化前: %dB\n" +
		"OrgColumn: %dB\n" +
		" Com: %dB\n" +
		" Token: %dB\n" +
		" IsValidBalCor: %dB\n" +
		" isValidAsset: %dB\n" +
		" Token': %dB\n" +
		" Token'': %dB\n" +
		" sizeof(dzkp): %dB\n" +
		" dzkp.proof: %dB\n" +
		" dzkp.G1: %dB\n" +
		" dzkp.Y1: %dB\n" +
		" dzkp.G2: %dB\n" +
		" dzkp.Y2: %dB\n" +
		" S: %dB\n" +
		" T: %dB\n", len(zkrowdata), unsafe.Sizeof(*zkrow), unsafe.Sizeof(*(zkrow.Columns["Org1"])),
		len(zkrow.Columns["Org1"].Commitment), len(zkrow.Columns["Org1"].AuditToken),
		unsafe.Sizeof(zkrow.Columns["Org1"].IsValidBalCor), unsafe.Sizeof(zkrow.Columns["Org1"].IsValidAsset),
		len(zkrow.Columns["Org1"].TokenPrime), len(zkrow.Columns["Org1"].TokenDoublePrime),
		unsafe.Sizeof(*(zkrow.Columns["Org1"].Dzkp)),
		len(zkrow.Columns["Org1"].Dzkp.Proof), len(zkrow.Columns["Org1"].Dzkp.G1),
		len(zkrow.Columns["Org1"].Dzkp.Y1), len(zkrow.Columns["Org1"].Dzkp.G2),
		len(zkrow.Columns["Org1"].Dzkp.Y2),
		len(zkrow.Columns["Org1"].S), len(zkrow.Columns["Org1"].T),)
	resRpProto := fmt.Sprintf("sizeof(rp)：%dB\n" +
		"rp.Comm：%dB\n" +
		"rp.A：%dB\n" +
		"rp.S：%dB\n" +
		"rp.T1：%dB\n" +
		"rp.T2：%dB\n" +
		"rp.Tau：%dB\n" +
		"rp.Th：%dB\n" +
		"rp.Mu：%dB\n" +
		"rp.Cy：%dB\n" +
		"rp.Cz：%dB\n" +
		"rp.Cx：%dB\n" +
		"sizeof(rp.IPP)：%dB\n" +
		"rp.IPP.L：%dB\n" +
		"rp.IPP.R：%dB\n" +
		"rp.IPP.A：%dB\n" +
		"rp.IPP.B：%dB\n", unsafe.Sizeof(*(zkrow.Columns["Org1"].Rp)), len(zkrow.Columns["Org1"].Rp.Comm),
		len(zkrow.Columns["Org1"].Rp.A), len(zkrow.Columns["Org1"].Rp.S),
		len(zkrow.Columns["Org1"].Rp.T1), len(zkrow.Columns["Org1"].Rp.T2),
		len(zkrow.Columns["Org1"].Rp.Tau), len(zkrow.Columns["Org1"].Rp.Th),
		len(zkrow.Columns["Org1"].Rp.Mu), len(zkrow.Columns["Org1"].Rp.Cy),
		len(zkrow.Columns["Org1"].Rp.Cz), len(zkrow.Columns["Org1"].Rp.Cx),

		unsafe.Sizeof(*(zkrow.Columns["Org1"].Rp.IPP)), len(zkrow.Columns["Org1"].Rp.IPP.L),
		len(zkrow.Columns["Org1"].Rp.IPP.R), len(zkrow.Columns["Org1"].Rp.IPP.A),
		len(zkrow.Columns["Org1"].Rp.IPP.B),
	)

	//return string(zkrow.Columns["Org2"].Commitment), nil // 当组织名字不存在时，报错： Multiple errors occurred: - Transaction processing for endorser [peer1.org2.example.com:10051]: Chaincode status Code: (500) UNKNOWN. Description: error in simulation: failed to execute transaction 60e3e0c44c54c8be3bcc5733903044f03f67425dd74d015c6cbfd77bdb2479b9: error sending: chaincode stream terminated - Transaction processing for endorser [peer1.org1.example.com:9051]: Chaincode status Code: (500) UNKNOWN. Description: error in simulation: failed to execute transaction 60e3e0c44c54c8be3bcc5733903044f03f67425dd74d015c6cbfd77bdb2479b9: error sending: chaincode stream terminated
	return res+"===="+resRpProto, nil
}

// Set stores the asset (both key and value) on the ledger. If the key exists,
// it will override the value with the new one
func set(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key and a value")
	}

	err := stub.PutState(args[0], []byte(args[1]))
	//err := stub.PutState("", []byte(args[1]))
	if err != nil {
		return "", fmt.Errorf("Failed to set asset: %s", args[0])
	}

	log.Println("调用了set！！！！！！！！！！！！！！")

	// 测试event
	var as []byte
	for _, a := range args {
		as = append(as, []byte(a)...) // golang中的append: https://www.cnblogs.com/baiyuxiong/p/4334266.html
	}
	err = stub.SetEvent("InvokeEvent", as)
	if err!=nil{
		return "", fmt.Errorf("failed to emit an event!")
	}


	return args[1], nil
}

// Get returns the value of the specified asset key
func get(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Incorrect arguments. Expecting a key")
	}
	value, err := stub.GetState(args[0])
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s with error: %s", args[0], err)
	}
	if value == nil {
		return "", fmt.Errorf("Asset not found: %s", args[0])
	}

	log.Println("调用了get！！！！！！！！！！！！！！")

	return string(value), nil
}

/*chaincode method*/
// 交易
func transfer(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	txSpeJsons := args[0]
	//txSpeStruct := TxSpecification{}
	//json.Unmarshal([]byte(txSpeJsons), &txSpeStruct)
	//fmt.Println("结构体", txSpeStruct)
	fmt.Println("结构体", string(txSpeJsons))
	// 调用ZkPutState，计算<Com, Token>，并在账本上添加一笔新的交易

	fmt.Println("调用ZkPutState_test")
	key := args[1]
	res, err := stub.ZkPutState_test(txSpeJsons, key) // 测试

	return res, err
	//return txSpeStruct.R[0].String(), nil
}

//监管
func audit(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	auditSpeJsons := args[0]
	key := args[1]
	//txSpeStruct := TxSpecification{}
	//json.Unmarshal([]byte(auditSpeJsons), &txSpeStruct)
	fmt.Println("结构体", string(auditSpeJsons))
	res, _ := stub.ZkAudit(auditSpeJsons, key) // 调用ZkAudit，计算<RP, DZKP, Token', Token''>，audit()可被周期性调用，实现automated auditing
	return res, nil
}

//验证
func validationStep1(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	key := args[0]
	orgNum, _ := strconv.Atoi(args[1]) // 组织数
	sk, _ := new(big.Int).SetString(args[2], 10) // 组织私钥
	org_name := args[3] // 进行验证的组织
	value, _ := new(big.Int).SetString(args[4], 10) // 组织实际的交易额

	res, err := stub.ZkVerifyOne(key, orgNum, sk, org_name, value)
	if err != nil{
		return "", err
	}
	return res, nil
}

// 验证某个组织
func validationStep2(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	key := args[0]
	orgNum, _ := strconv.Atoi(args[1]) // 组织数
	sk, _ := new(big.Int).SetString(args[2], 10) // 组织私钥
	org_name := args[3] // 进行验证的组织

	res, err := stub.ZkVerifyTwo(key, orgNum, org_name, sk)
	if err != nil{
		return "", err
	}
	return res, nil
}

// 验证所有组织
func validationStep2All(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	key := args[0]
	orgNum, _ := strconv.Atoi(args[1]) // 组织数

	res, err := stub.ZkVerifyTwoAll(key, orgNum)
	if err != nil{
		return "", err
	}
	return res, nil
}

//验证
func validation(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	key := args[0]
	orgNum, _ := strconv.Atoi(args[1]) // 组织数
	sk, _ := new(big.Int).SetString(args[2], 10) // 组织私钥
	org_name := args[3] // 进行验证的组织
	value, _ := new(big.Int).SetString(args[4], 10) // 组织实际的交易额
	flag := args[5]

	// 完成两阶段验证，分别验证两组NIZK
	if flag=="Step1"{
		res, err := stub.ZkVerifyOne(key, orgNum, sk, org_name, value)
		if err != nil{
			return "", err
		}
		return res, nil
	} else if flag=="Step2" {
		res, err := stub.ZkVerifyTwo(key, orgNum, org_name, sk)
		if err != nil{
			return "", err
		}
		return res, nil
	} else {
		return "只有两个阶段的验证", nil
	}
}

// 测试函数，用来测试shim中添加的API能否被正确调用
func comm(stub shim.ChaincodeStubInterface, args []string) (string, error){
	if len(args) != 1 {
		return "", fmt.Errorf("Incorrect arguments. Need one amounts!")
	}
	amount := args[0]
	new_amount := stub.Cal_commitment(amount)
	//return "原来chaincode method返回的第一个string就是所谓的payload啊！！", nil
	fmt.Println("调用了comm函数")
	return new_amount, nil
}

////preimageBytesHex := "0x726f6f74726f6f74"
//hashLock := "0242c0436daa4c241ca8a793764b7dfb50c223121bb844cf49be670a3af4dd18"
//preImage := "rootroot"
// Hash(preImage) 计算哈希值
func Hash(preImage string) string {
	sha256Passwd := sha256.Sum256([]byte(preImage))
	return hex.EncodeToString(sha256Passwd[:])
}

// 返回htlc结构体的id
func lock(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	//log.Println(fmt.Sprintf("调用链码lock：%vms", time.Now().UnixNano()/ 1e6 ))
	hashValue := args[0]
	TStr := args[1]
	txSpeJsons := args[2]
	key := args[3]
	flag := args[4]

	// 判断出hashValue是原像而非哈希值
	if flag!= "hashValue"{
		preImage := hashValue
		hashValue = Hash(preImage)
	}

	// 1. 哈希值、时间值上链
	T, _ := strconv.ParseInt(TStr, 10, 64) // deltaT
	timeLock := time.Now().Unix() + T  // 计算时间锁

	htlc := HTLC{
		HashValue:   hashValue,
		TimeLock:    timeLock,
		PreImage:    "",
		State:       HashLOCK,
		TxKey:  	 key, // 使得每笔交易计算出的htlc结构体的哈希值不同
	}

	htlcByte, _ := json.Marshal(htlc)
	idByte := sha256.Sum256(htlcByte)
	id := hex.EncodeToString(idByte[:])
	k := fmt.Sprintf(HTLCPrefix, id)

	if err := stub.PutState(k, htlcByte); err != nil {
		return "", fmt.Errorf("保存htlc结构体失败", err)
	}

	// 2. 记录一行
	res, err := stub.ZkPutState_test(txSpeJsons, key) 	// 计算<Com, Token>，并在账本上添加一笔新的交易
	if err!=nil{
		return "锁定时记账失败", nil
	}
	_ = res

	// 3. 设置事件
	var as []byte
	//as = append(as, []byte("锁定资产时的payload")...)
	//as = append(as, []byte(stub.GetTxID())...)
	as = append(as, []byte(key)...)
	err = stub.SetEvent("InvokeEvent_lock", as)
	if err!=nil{
		return "", fmt.Errorf("failed to emit an event!")
	}

	log.Println(fmt.Sprintf("调用链码lock完成：%vms", time.Now().UnixNano()/ 1e6 ))
	return id,nil
	//return res, err
}

//// 返回htlc结构体的id
//func lock(stub shim.ChaincodeStubInterface, args []string) (string, error) {
//	hashValue := args[0]
//	timeLockStr := args[1]
//	// 1. 哈希值、时间值上链
//	timeLock, _ := strconv.ParseInt(timeLockStr, 10, 64)
//
//	htlc := HTLC{
//		HashValue:   hashValue,
//		TimeLock:    timeLock,
//		PreImage:    "",
//		State:       HashLOCK,
//	}
//
//	htlcByte, _ := json.Marshal(htlc)
//	idByte := sha256.Sum256(htlcByte)
//	id := hex.EncodeToString(idByte[:])
//	key := fmt.Sprintf(HTLCPrefix, id)
//
//	if err := stub.PutState(key, htlcByte); err != nil {
//		//return "",shim.Error(err.Error())
//		return "",fmt.Errorf("保存htlc结构体失败", err)
//	}
//
//	// 2. 记录一行
//	stub.ZkPutState()
//	return id,nil
//}

//func withdraw(h string)  {
//	// 先调用withdraw()的一方，通过参数传入原像h；后调用withdraw()的一方，需要从本条链的数据库中读取先调用withdraw的一方保存的原像h
//
//	// 从本条链的数据库中读取createHash()中保存的变量midaddress, receiver, amountStr
//
//	// createHash和withdraw分别由交易的双方执行，并通过HTLC结构体共享调用transfer函数需要的参数
//	//transfer(midaddress, receiver, amountStr, h) // 中间账户向receiver转账
//
//	// 先调用withdraw的一方，领取资产后，将原像保存到本条链的数据库
//}

func withdraw(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	log.Println(fmt.Sprintf("调用链码withdraw：%vms", time.Now().UnixNano()/ 1e6 ))
	preImage := args[0]
	id := args[1]
	key := args[2]

	// 1. 读取哈希值、时间值
	k := fmt.Sprintf(HTLCPrefix, id)
	htlcByte, err := stub.GetState(k)
	if err != nil {
		return "failed",fmt.Errorf("读取htlc结构体失败", err)
	}
	if  htlcByte== nil {
		return "failed",fmt.Errorf("htlc结构体为空值！", err)
	}

	htlc := &HTLC{}
	if err = json.Unmarshal(htlcByte, htlc); err != nil {
		return "failed",fmt.Errorf("解析htlc失败", err)
	}

	if htlc.State != HashLOCK {
		return "failed",fmt.Errorf("this htlc transaction state is error")
	} // 检查是否已锁定

	// 2. 设置事件
	var as []byte
	as = append(as, []byte("领取资产时的payload")...)
	err = stub.SetEvent("InvokeEvent_withdraw", as)
	if err!=nil{
		return "事件错", fmt.Errorf("failed to emit an event!", err)
	}

	// 3. 判断能否领取资产
	// a. 在规定时间内提供了正确的原像
	if strings.Compare(htlc.HashValue, Hash(preImage)) ==0 && htlc.TimeLock>=time.Now().Unix() {
		htlc.State = Received
		htlcByte, err = json.Marshal(htlc)
		if err != nil {
			return "failed",fmt.Errorf("")
		}
		if err = stub.PutState(k, htlcByte); err != nil {
			return "failed",fmt.Errorf("")
		}
		return "领取资产成功", nil
	} else {
		if htlc.TimeLock > time.Now().Unix() {
			return "failed",fmt.Errorf("time is not expirate") // 检查是否超时
		}

		if htlc.State != HashLOCK {
			return "failed",fmt.Errorf("this htlc transaction state is error")
		} // 检查是否已锁定

		// b. 回撤
		//stub.ZkPutState() // 反向转账
		stub.DelState(key)

		//if strings.Compare(htlc.HashValue, Hash(preImage)) !=0{
		//	return "#"+htlc.HashValue+"#"+Hash(preImage), nil
		//}else if htlc.TimeLock<time.Now().Unix() {
		//	return "超时", nil
		//}
		return "withdraw failed", nil
	}
}

// 根据超时情况回撤
//func refund()  {
//	if Alice超时{
//		// 此时双方都未成功领取对方的资产
//		// Alice由于持有h，自己是可以从中间账户mid1中取回资产的
//		// Bob没有h，因此Bob需要能够从中间账户mid2中取回资产
//	}
//	else Bob超时{
//		// 此时Alice已成功领取Bob锁定的资产
//		// Alice需要归还Bob在chain_2的资产
//		// Alice从中间账户mid1中取回资产
//	}
//}

// 在withdraw中调用refund
//func refund(stub shim.ChaincodeStubInterface, args []string) error {
//	//preImage := args[0]
//	id := args[1]
//
//	// 1. 读取哈希值、时间值
//	key := fmt.Sprintf(HTLCPrefix, id)
//	htlcByte, err := stub.GetState(key)
//	if err != nil {
//		return fmt.Errorf("读取htlc结构体失败", err)
//	}
//
//	htlc := &HTLC{}
//	if err = json.Unmarshal(htlcByte, htlc); err != nil {
//		return fmt.Errorf("解析htlc失败")
//	}
//
//	if htlc.TimeLock > time.Now().Unix() {
//		return fmt.Errorf("time is not expirate") // 检查是否超时
//	}
//
//	if htlc.State != HashLOCK {
//		return fmt.Errorf("this htlc transaction state is error")
//	} // 检查是否已锁定
//
//	// 2. 回撤
//	stub.ZkPutState()
//
//	return nil
//
//}

// main function starts up the chaincode in the container during instantiate
func main() {
	if err := shim.Start(new(SimpleAsset)); err != nil {
		fmt.Printf("Error starting SimpleAsset chaincode: %s", err)
	}
}
