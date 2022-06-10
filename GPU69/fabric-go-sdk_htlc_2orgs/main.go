package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fabric-go-sdk/sdkInit"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	fabAPI "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"

	//"github.com/mit-dci/zksigma"
	//"math/big"
)

const (
	cc_name = "simplecc"
	cc_version = "1.0.0"
)

var App sdkInit.Application
//// string转int
//stringToInt, err = strconv.Atoi(stringValue)
//fmt.Println("stringToInt:", stringToInt, ";err:", err)
//// string转int64
//stringToInt64, err = strconv.ParseInt(stringValue, 10, 64)
//fmt.Println("stringToInt64:", stringToInt64, ";err:", err)
//// int转string
//intToString = strconv.Itoa(intValue)
//fmt.Println("intToString:", intToString)
//// int64转string
//int64ToString = strconv.FormatInt(int64Value, 10)
//fmt.Println("int64ToString:", int64ToString)
//// string转[]byte
//stringToByte = []byte(stringValue)
//fmt.Println("stringToByte:", stringToByte)
//// []byte转string
//byteToString = string(byteValue)
//fmt.Println("byteToString:", byteToString)

func InitLedger(orgPkSk sdkInit.OrgPkSk, asset []int64, channelIdx int)  {
	fmt.Println(">> 生成transaction specification用于初始化二维账本......")
	txSpeInit := sdkInit.GetRforInit(sdkInit.ZKLedgerCurve, asset[:])
	//fmt.Println(txSpe.Pk)
	txSpeInit.Pk = orgPkSk.Pk
	//fmt.Println(txSpe.Pk)
	fmt.Println(">> transaction specification生成完成")
	fmt.Println("transaction specification:", txSpeInit)
	txSpeInitJsons, err := json.Marshal(txSpeInit)
	if err != nil {
		fmt.Println(err.Error())
	}

	args := []string{"initLedger", string(txSpeInitJsons), "0"}
	ret, err := App.Set(args, channelIdx, 0)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("<--- 初始化账本函数initLedger测试　--->：", ret)

	args = []string{"read_from_ledger", "0"}
	ret, err = App.Set(args, channelIdx, 1)
	//response, err = App.Get(e) 到底是用set还是用get
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("<--- 读取账本函数read_from_ledger测试　--->：", ret)

	fmt.Sprintf("成功初始化通道%d上账本余额", channelIdx)
}

func createTxSpe(spenderIdx int, receiverIdx int, value int64) sdkInit.TxSpecification {
	//fmt.Println(">> 生成transaction specification......")
	txSpe := sdkInit.GetR(sdkInit.ZKLedgerCurve, value, privateLedger.orgNum, spenderIdx, receiverIdx) // 当前只有两个组织，Org1是支出方，Org2是接收方
	//fmt.Println(txSpe.Pk)
	txSpe.Pk = privateLedger.orgPkSk.Pk
	//fmt.Println(txSpe.Pk)
	//fmt.Println(">> transaction specification生成完成")
	return txSpe
}

func Lock(orgPkSk sdkInit.OrgPkSk, txSpe sdkInit.TxSpecification, orgNum int, hashValue string, T int64, value int64, spenderIdx int, receiverIdx int, channelIdx int, txKey string, flag string) string {
	//fmt.Println("transaction specification:", txSpe)
	txSpeJsons, err := json.Marshal(txSpe)
	if err != nil {
		fmt.Println(err.Error())
	}
	arg := []string{"lock", hashValue, strconv.FormatInt(T, 10), string(txSpeJsons), txKey, flag}
	id, err := App.Set(arg, channelIdx, spenderIdx)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(fmt.Sprintf(">> Tx%v|Org%d锁定链%d的资产：id%d=%s",txKey, spenderIdx+1, channelIdx+1, channelIdx+1, id))

	return id
}

func Withdraw(preImage, id, txKey string, channel_idx, org_idx int) bool {
	//time.Sleep(time.Millisecond*200)
	arg:=[]string{"withdraw", preImage, id, txKey}
	ret, err := App.Set(arg, channel_idx, org_idx)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(fmt.Sprintf(">> Tx%v|Org%d领取链%d资产：%s",txKey, org_idx+1, channel_idx+1, ret))
	if ret=="领取资产成功"{
		return true // 领取成功
	} else {
		return false
	}
}

func Audit(orgPkSk sdkInit.OrgPkSk, orgNum int, R []*big.Int, spenderIdx int, receiverIdx int, balance, value int64, channelIdx int, txKey string)  {
	//fmt.Println(">> 生成audit specification......")
	auditSpe := sdkInit.CreateAuditSpecification(sdkInit.ZKLedgerCurve, big.NewInt(balance), value, orgNum, spenderIdx, receiverIdx) // 当前只有两个组织，Org0是支出方，Org1是接收方
	auditSpe.Pk = orgPkSk.Pk
	auditSpe.Sk = orgPkSk.Sk[spenderIdx] // 支出方的sk
	auditSpe.R = R // 所有组织计算token用到的r
	auditSpe.SpenderIdx = spenderIdx
	//fmt.Println(auditSpe.ValueforRangeProof)
	//fmt.Println(">> audit specification生成完成")
	auditSpeJsons, err := json.Marshal(auditSpe)
	if err != nil {
		fmt.Println(err.Error())
	}
	args := []string{"audit",string(auditSpeJsons) , txKey}
	ret, err := App.Set(args, channelIdx, spenderIdx)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(fmt.Sprintf(">> Tx%v|Org%d在链%d调用audit：%s ",txKey, spenderIdx+1, channelIdx+1, ret))
}

func VerifyOne(orgPkSk sdkInit.OrgPkSk, txSpe sdkInit.TxSpecification, orgNum int, channelIdx int, orgIdx int, txKey string)  {
	//time.Sleep(time.Second*2) // 等待转账写入世界状态
	valueforVerify := txSpe.Value[orgIdx].String() //实际上这个值是从私有数据库中获取的
	args := []string{"validationStep1", txKey, strconv.Itoa(orgNum), orgPkSk.Sk[orgIdx].String(), "Org" + strconv.Itoa(orgIdx+1), valueforVerify} // 进行第一阶段的验证
	ret, err := App.Set(args, channelIdx, orgIdx) // Org{orgIdx+1}在Channel{channelIdx}上的通道客户端调用链码
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(fmt.Sprintf(">>>> Tx%v|Org%d对链%d进行阶段1验证：%s",txKey, orgIdx+1, channelIdx+1, ret))
}

// 只验证一个组织的证明
func VerifyTwo(receiverIdx int, txKey string, channel_idx, org_idx int)  {
	i := receiverIdx
	args := []string{"validationStep2", txKey, strconv.Itoa(privateLedger.orgNum), privateLedger.orgPkSk.Sk[i].String(), "Org" + strconv.Itoa(i+1)}
	ret, err := App.Set(args, channel_idx, org_idx)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(fmt.Sprintf(">> Tx%v|Org%d对链%d进行阶段2验证：%s",txKey, org_idx+1, channel_idx+1, ret))
}

//// 验证所有组织的证明
//func VerifyTwoAll(txKey string, channel_idx int)  {
//	for i:=0;i<privateLedger.orgNum;i++{
//		go VerifyTwo(i, txKey, channel_idx, i)
//	}
//}

// receiverIdx充当监管者，验证所有组织的证明
func VerifyTwoAll(receiverIdx int, txKey string, channel_idx int)  {
	i := receiverIdx
	args := []string{"validationStep2All", txKey, strconv.Itoa(privateLedger.orgNum)}
	ret, err := App.Set(args, channel_idx, i)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(fmt.Sprintf(">> Tx%v|Org%d对链%d进行阶段2验证：%s",txKey, i+1, channel_idx+1, ret))
}

// 根据订阅到的event决定调用哪个函数
func FilteredBlockListenerSelect(ec *event.Client, listenerTag string, channelIdx int, orgIdx int) fabAPI.Registration {
	// Register monitor filtered block event
	fbeReg, fbeCh, err := ec.RegisterFilteredBlockEvent()
	if err != nil {
		log.Printf(listenerTag+"Register filtered block event error: %v", err)
	}

	// Receive filtered block event
	go func() {
		for e := range fbeCh {
			// 1. 打印区块信息
			//log.Printf("<============%vReceive filterd block event:============>\n" +
			//	"Number: %v\nChannelID: %v\nlen(transactions): %v\nSourceURL: %v",
			//	listenerTag, e.FilteredBlock.Number, e.FilteredBlock.ChannelId, len(e.FilteredBlock.
			//		FilteredTransactions), e.SourceURL)
			// 2. 打印区块中的交易信息
			for i, tx := range e.FilteredBlock.FilteredTransactions {
				//payload := string(tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().Payload)
				eventname := tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().EventName
				txVadCode := tx.TxValidationCode.String() // 交易验证码
				txNum := len(tx.GetTransactionActions().ChaincodeActions) //
				if txNum!=1{
					fmt.Println("1个tx中有多个tx Action!!!!!!!!!")
				}
				//fmt.Println("eventname:", eventname)
				//fmt.Println("payload:", payload)
				//fmt.Println("长度:", len(tx.GetTransactionActions().ChaincodeActions))

				// a. 打印
				//log.Printf("<======Block%v中的Tx%d:======>",e.FilteredBlock.Number, i)
				//fmt.Printf(" tx index: %d\n type: %v\n txid: %v\n validation code: %v\n event name: %v\n",
				//	i, tx.Type, tx.Txid, tx.TxValidationCode, eventname)
				//fmt.Printf("%v监听到了区块事件%v\n", listenerTag, eventname)
				_ = i

				// b. 根据EventName，各组织对账本进行验证
				if eventname=="InvokeEvent_lock" && txVadCode=="VALID"{ // 调用链码中的lock函数发出的事件
					orgPkSk := privateLedger.orgPkSk
					orgNum := privateLedger.orgNum
					//txKey := privateLedger.txKeyList[len(privateLedger.txKeyList)-1] // 获取最新的交易。0423补充：获取最新的交易的做法对于功能测试是没问题的，但当系统中有多个并发的交易请求时，就报报错；所以改成了从事件中获取
					txKey := string(tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().Payload) // 从事件中获取
					//fmt.Println(fmt.Sprintf("资产锁定添加到链%d的块%v中", channelIdx+1, e.FilteredBlock.Number))
					//log.Println(">>>>", listenerTag)
					if channelIdx==0{
						//tmpIdx, _ := strconv.Atoi(txKey)
						//txSpe := privateLedger.txSpe1List[tmpIdx-1]
						//txSpe := privateLedger.txSpe1Map[txKey]
						txSpe, ok := privateLedger.txSpe1Map.readMap(txKey)
						if ok!=true{
							fmt.Println("Map中找不到", txKey)
							os.Exit(-1)
						}
						go VerifyOne(orgPkSk, txSpe, orgNum, channelIdx, orgIdx, txKey)
					}else if channelIdx==1{
						//tmpIdx, _ := strconv.Atoi(txKey)
						//txSpe := privateLedger.txSpe2List[tmpIdx-1]
						//txSpe := privateLedger.txSpe2Map[txKey]
						txSpe, ok := privateLedger.txSpe2Map.readMap(txKey)
						if ok!=true{
							fmt.Println("Map中找不到", txKey)
							os.Exit(-1)
						}
						go VerifyOne(orgPkSk, txSpe, orgNum, channelIdx, orgIdx, txKey)
					}
				} else if eventname=="InvokeEvent_audit" && txVadCode=="VALID"{ // 调用链码中的audit函数发出的事件
					// 暂时待定
				}
			}
			//log.Println("<============END============>")
		}
	}()
	return fbeReg
}

// 适用于并发环境的Map
type SMap struct {
	sync.RWMutex
	Map map[string]sdkInit.TxSpecification
}

func (l *SMap) readMap(key string) (sdkInit.TxSpecification, bool) {
	l.RLock()
	value, ok := l.Map[key]
	l.RUnlock()
	return value, ok
}

func (l *SMap) writeMap(key string, value sdkInit.TxSpecification) {
	l.Lock()
	l.Map[key] = value
	l.Unlock()
}

// 一个全局变量，方便传参
type PrivateLedger struct {
	// 区块链网络
	orgPkSk sdkInit.OrgPkSk // 所有Org的公私钥
	orgNum int // 系统中的组织数
	// 交易信息
	txSpe1List []sdkInit.TxSpecification // 存放第Channel1上所有的txSpe
	txSpe2List []sdkInit.TxSpecification // 存放第Channel2上所有的txSpe

	// 适用于并发环境
	//txSpe1Map map[string]sdkInit.TxSpecification
	//txSpe2Map map[string]sdkInit.TxSpecification
	// 忽视了Map本身不适用于并发环境，重写

	// 加同步锁，适用于并发环境
	txSpe1Map *SMap
	txSpe2Map *SMap

	txKeyList []string // 账本中所有交易的key
}
var privateLedger = PrivateLedger{}

func main() {
	//log.SetFlags(log.Ldate |log.Ltime |log.Lmicroseconds)
	// init orgs information
	orgs := []*sdkInit.OrgInfo{
		{
			OrgAdminUser:  "Admin",
			OrgName:       "Org1",
			OrgMspId:      "Org1MSP",
			OrgUser:       "User1", // OrgUser是用来load identity文件的，这个应该是不需要改，每个组织都一样的
			OrgPeerNum:    2,
			OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org1MSPanchors1.tx", "./fixtures/channel-artifacts/Org1MSPanchors2.tx"}, // 锚节点
			//OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org1MSPanchors1.tx"}, // 锚节点
			//OrgAnchorFile: "./fixtures/channel-artifacts/Org1MSPanchors1.tx",
		},
		{
			OrgAdminUser:  "Admin",
			OrgName:       "Org2",
			OrgMspId:      "Org2MSP",
			OrgUser:       "User1",
			OrgPeerNum:    2,
			OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org2MSPanchors1.tx", "./fixtures/channel-artifacts/Org2MSPanchors2.tx"}, // 锚节点
		},
		//{
		//	OrgAdminUser:  "Admin",
		//	OrgName:       "Org3",
		//	OrgMspId:      "Org3MSP",
		//	OrgUser:       "User1",
		//	OrgPeerNum:    1,
		//	OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org3MSPanchors1.tx", "./fixtures/channel-artifacts/Org3MSPanchors2.tx"}, // 锚节点
		//},
		//{
		//	OrgAdminUser:  "Admin",
		//	OrgName:       "Org4",
		//	OrgMspId:      "Org4MSP",
		//	OrgUser:       "User1",
		//	OrgPeerNum:    1,
		//	OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org4MSPanchors1.tx", "./fixtures/channel-artifacts/Org4MSPanchors2.tx"}, // 锚节点
		//},
		//{
		//	OrgAdminUser:  "Admin",
		//	OrgName:       "Org5",
		//	OrgMspId:      "Org5MSP",
		//	OrgUser:       "User1",
		//	OrgPeerNum:    1,
		//	OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org5MSPanchors1.tx", "./fixtures/channel-artifacts/Org5MSPanchors2.tx"}, // 锚节点
		//},
		//{
		//	OrgAdminUser:  "Admin",
		//	OrgName:       "Org6",
		//	OrgMspId:      "Org6MSP",
		//	OrgUser:       "User1",
		//	OrgPeerNum:    1,
		//	OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org6MSPanchors1.tx", "./fixtures/channel-artifacts/Org6MSPanchors2.tx"}, // 锚节点
		//},
		//{
		//	OrgAdminUser:  "Admin",
		//	OrgName:       "Org7",
		//	OrgMspId:      "Org7MSP",
		//	OrgUser:       "User1",
		//	OrgPeerNum:    1,
		//	OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org7MSPanchors1.tx", "./fixtures/channel-artifacts/Org7MSPanchors2.tx"}, // 锚节点
		//},
		//{
		//	OrgAdminUser:  "Admin",
		//	OrgName:       "Org8",
		//	OrgMspId:      "Org8MSP",
		//	OrgUser:       "User1",
		//	OrgPeerNum:    1,
		//	OrgAnchorFile: []string{"./fixtures/channel-artifacts/Org8MSPanchors1.tx", "./fixtures/channel-artifacts/Org8MSPanchors2.tx"}, // 锚节点
		//},
	}

	// init sdk env info
	info := sdkInit.SdkEnvInfo{
		ChannelID:        []string{"mychannel1", "mychannel2"},
		ChannelConfig:    []string{"./fixtures/channel-artifacts/channel1.tx", "./fixtures/channel-artifacts/channel2.tx"},
		//ChannelID:        []string{"mychannel1"},
		//ChannelConfig:    []string{"./fixtures/channel-artifacts/channel1.tx"},
		//ChannelID:        "mychannel1",
		//ChannelConfig:    "./fixtures/channel-artifacts/channel1.tx",
		Orgs:             orgs, // 是一个数组
		OrdererAdminUser: "Admin",
		OrdererOrgName:   "OrdererOrg",
		OrdererEndpoint:  "orderer.example.com",
		ChaincodeID:      cc_name,
		ChaincodePath:    "./chaincode/",
		ChaincodeVersion: cc_version,
	}

	// sdk setup
	sdk, err := sdkInit.Setup("config.yaml", &info) // 创建msp客户端，资源管理客户端；看起来只需要执行一遍？？？
	if err != nil {
		fmt.Println(">> SDK setup error:", err)
		os.Exit(-1)
	}
	//// 查看组织的公私钥
	//if err := sdkInit.GetOrgMsp(&info); err != nil {
	//	fmt.Println(">> Create channel and join error:", err)
	//	os.Exit(-1)
	//}
	//// 暂停20s
	//duration := time.Duration(20)*time.Second
	//time.Sleep(duration)
	// create channel and join
	if err := sdkInit.CreateAndJoinChannel(&info); err != nil {
		fmt.Println(">> Create channel and join error:", err)
		os.Exit(-1)
	}

	// create chaincode lifecycle
	if err := sdkInit.CreateCCLifecycle(&info, 1, false, sdk); err != nil { // sequence是什么意思？
		fmt.Println(">> create chaincode lifecycle error: %v", err)
		os.Exit(-1)
	}

	// invoke chaincode set status
	fmt.Println(">> 通过链码外部服务设置链码状态......")

	//if err := info.InitService(info.ChaincodeID, info.ChannelID, info.Orgs[0], sdk);err != nil{
	//if err := info.InitService(info.ChaincodeID, info.ChannelID[0], info.Orgs[0], sdk);err != nil{
	//	fmt.Println("InitService successful")
	//	os.Exit(-1)
	//}
	fmt.Println("<---------------创建Channel Client-------------------->")
	channelNum := len(info.ChannelID)
	orgNum := len(info.Orgs)
	// 确定通道客户端数组info.Client的维度，其中第一维是通道，第二维是组织；切片初始化参考自https://studygolang.com/articles/34434
	info.Client = make([][]*channel.Client, channelNum) // 二维切片
	for i := range info.Client {
		info.Client[i] = make([]*channel.Client, orgNum)
	}
	for i:=0; i<channelNum; i++{
		for j:=0; j<orgNum; j++{
			info.Client[i][j], err = info.InitService(info.ChaincodeID, info.ChannelID[i], info.Orgs[j], sdk) // 为org_j创建在channel_i上的client
			if err != nil{
				fmt.Println("InitService successful")
				os.Exit(-1)
			}
			//fmt.Println(info.Client[i][j]) //
		}
	}

	fmt.Println(">> 生成组织的公私钥对......")
	//pk, sk := sdkInit.Generate_sk_pk_test()
	orgPkSk := sdkInit.Generate_sk_pk(orgNum)
	//fmt.Println(orgPkSk.Pk)
	fmt.Println(">> 秘钥生成完成")
	privateLedger.orgPkSk = orgPkSk
	privateLedger.orgNum = orgNum
	//privateLedger.txSpe1Map = make(map[string]sdkInit.TxSpecification)
	//privateLedger.txSpe2Map = make(map[string]sdkInit.TxSpecification)
	privateLedger.txSpe1Map = &SMap{
		Map: make(map[string]sdkInit.TxSpecification),
	}
	privateLedger.txSpe2Map = &SMap{
		Map: make(map[string]sdkInit.TxSpecification),
	}

	App=sdkInit.Application{
		SdkEnvInfo: &info,
	}

	args := []string{"read_from_ledger", "二维账本第一行"}
	ret, err := App.Set(args, 1, 1)
	//response, err = App.Get(e) 到底是用set还是用get
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("<--- 读取账本函数read_from_ledger测试　--->：", ret)

	// 初始化余额
	//asset1 := [2]int64 {100, 100} // 初始化数组长度只能用常量
	//asset2 := [2]int64 {200, 200}
	asset1 := []int64{}
	for i:=0;i<orgNum;i++{
		asset1 = append(asset1, 10000000) // 所有组织在链1上的初始资产均为1000
	}
	asset2 := []int64{}
	for i:=0;i<orgNum;i++{
		asset2 = append(asset2, 10000000) // 所有组织在链2上的初始资产均为2000
	}
	fmt.Println("asset1", asset1)
	fmt.Println("asset2", asset2)
	// 初始化账本
	InitLedger(orgPkSk, asset1[:], 0)
	InitLedger(orgPkSk, asset2[:], 1)
	if len(asset1)!=orgNum{
		fmt.Println("初始余额设置错误，需为每个组织初始化余额")
		os.Exit(0)
	}

	fmt.Println("<---------------创建Event Client-------------------->")
	info.EventClient = make([][]*event.Client, channelNum)
	for i := range info.EventClient {
		info.EventClient[i] = make([]*event.Client, orgNum)
	}
	for i:=0; i<channelNum; i++{
		for j:=0; j<orgNum; j++{
			info.EventClient[i][j] = sdkInit.CreateEventClient(info.ChannelID[i], info.Orgs[j], sdk) // 为org_j创建在channel_i上的eventclient

			// 所有组织订阅block event
			ec := info.EventClient[i][j]
			//defer ec.Unregister(sdkInit.BlockListener(ec))
			//listenerTag := fmt.Sprintf("Org%d在Channel%d上的listener监听到了区块事件", j+1, i+1)
			listenerTag := fmt.Sprintf("Org%d监听到通道%d上的区块事件", j+1, i+1)
			//defer ec.Unregister(sdkInit.FilteredBlockListener(ec, listenerTag))
			defer ec.Unregister(FilteredBlockListenerSelect(ec, listenerTag, i, j))
		}
	}
	// Org2订阅Channel1上的block event
	//ec := info.EventClient[0][1]
	//defer ec.Unregister(sdkInit.BlockListener(ec))
	//defer ec.Unregister(sdkInit.FilteredBlockListener(ec))
	fmt.Println("<--------------------------------------------------->")

	//args = []string{"testsize", "0"}
	//ret, err = App.Set(args, 0, 1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("<--- 测试密码学原语空间开销　--->：", ret)
	//
	//time.Sleep(time.Hour * 2400)


	fmt.Println("<---------------监听并响应HTTP请求-------------------->")

	r := gin.Default() // gin.Default()返回engine对象

	// 处理HTTP请求的接口
	r.POST("/htlc/testinvoke", test) // 测试
	r.POST("/htlc/lock", lock) //
	r.POST("/htlc/withdraw", withdraw) //
	r.POST("/htlc/audit", audit) //
	r.POST("/htlc/verifytwo", verifytwo) //
	r.POST("/htlc/verifytwoall", verifytwoall) //

	r.Run(":9191") // 监听HTTP请求

	fmt.Println("<--------------------------------------------------->")

	time.Sleep(time.Hour * 2400)




	// Org2调用channel1的链码
	//a:=[]string{"set","资产ID","---------------------"}
	//txid, err := App.Set(a, 0, 1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("<--- 添加信息　--->：", txid)
	//
	//// Org2调用channel1的链码
	//a=[]string{"set","资产ID","======================="}
	//txid, err = App.Set(a, 0, 1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("<--- 添加信息　--->：", txid)
	//
	//// Org2调用channel2的链码
	//a=[]string{"set","资产ID","-=-=-=-=-=-=-=-=-=-=-=-=-="}
	//txid, err = App.Set(a, 1, 1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("<--- 添加信息　--->：", txid)
	//
	//c := []string{"comm", "77"} //
	//txid, err := App.Set(c, 0, 2)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("<--- 计算承诺测试　--->：", txid)






	fmt.Println("<------------------------------------ 跨链交易　------------------------------------>")
	// 哈西时间锁参数
	var T1 int64 = 10 // 时间锁1，单位秒
	var T2 int64 = 5 // 时间锁2
	preImage := "rootroot" // 哈希值，加锁时用
	hashValue := "0242c0436daa4c241ca8a793764b7dfb50c223121bb844cf49be670a3af4dd18" // 哈希原像，解锁时用；Hash_value = Hash(preimage)
	//timeLock1 := time.Now().Unix() + T1
	txKey := "1" // 当前是第一笔跨链交易
	privateLedger.txKeyList = append(privateLedger.txKeyList, txKey)

	//  <--- Org1锁定chain1上的资产　--->
	value1 := int64(30) // 锁定金额
	spenderIdx1 := 0
	receiverIdx1 := 1
	txSpe := createTxSpe(spenderIdx1, receiverIdx1, value1)
	//privateLedger.txSpe1List = append(privateLedger.txSpe1List, txSpe)
	//privateLedger.txSpe1Map[txKey] = txSpe
	privateLedger.txSpe1Map.writeMap(txKey, txSpe)

	id1 := Lock(orgPkSk, txSpe, orgNum, preImage, T1, value1, spenderIdx1, receiverIdx1, 0, txKey, "preImage")

	//  <--- org2获得id1，hashVlaue　--->
	fmt.Println("<--- Org2获得id1，hashVlaue　--->")

	//timeLock2 := time.Now().Unix() + T2
	//  <--- Org2锁定chain2上的资产　--->
	value2 := int64(50)
	spenderIdx2 := 1
	receiverIdx2 := 0
	txSpe2 := createTxSpe(spenderIdx2, receiverIdx2, value2)
	//privateLedger.txSpe2List = append(privateLedger.txSpe2List, txSpe2)
	//privateLedger.txSpe2Map[txKey] = txSpe
	privateLedger.txSpe2Map.writeMap(txKey, txSpe2)

	id2 := Lock(orgPkSk, txSpe2, orgNum, hashValue, T2, value2, spenderIdx2, receiverIdx2, 1, txKey, "hashValue")

	//  <--- Org1获得id2　--->
	fmt.Println("<--- Org1获得id2　--->")

	//  <--- Org1领取Org2锁定在chain2上的资产　--->
	Withdraw(preImage, id2, txKey, 1, 0)

	fmt.Println("<--- Org2获得preImage　--->")

	//  <--- Org2领取Org1锁定在chain1上的资产　--->
	Withdraw(preImage, id1, txKey, 0, 1)

	//  <--- 监管流程　--->
	fmt.Println("<------------------------------------ 监管　------------------------------------>")
	//Audit(orgPkSk, orgNum, txSpe.R, spenderIdx1, receiverIdx1, asset1[spenderIdx1]-value1, value1, 0, txKey)
	//VerifyTwo(receiverIdx1, txKey, 0, receiverIdx1) // chain1上的接收方Org2，验证证明
	//
	//Audit(orgPkSk, orgNum, txSpe2.R, spenderIdx2, receiverIdx2, asset2[spenderIdx2]-value2, value2, 1, txKey) // 注意要传入的R与交易时的R一致
	//VerifyTwo(receiverIdx2, txKey, 1, receiverIdx2) // chain2上的接收方Org1，验证证明

	Audit(orgPkSk, orgNum, txSpe.R, spenderIdx1, receiverIdx1, asset1[spenderIdx1]-value1, value1, 0, txKey)
	VerifyTwoAll(receiverIdx1, txKey, 0) // 验证chain1证明

	Audit(orgPkSk, orgNum, txSpe2.R, spenderIdx2, receiverIdx2, asset2[spenderIdx2]-value2, value2, 1, txKey) // 注意要传入的R与交易时的R一致
	VerifyTwoAll(receiverIdx2, txKey, 1) // 验证chain1证明

	fmt.Println("两条链上的范围证明、析取证明均验证通过，跨链交易通过监管")
	fmt.Println("<------------------------------------ 结束　------------------------------------>")
	// asset两个数组也需要更新吧

	//args = []string{"testsize", txKey}
	//ret, err = App.Set(args, 0, 1)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("<--- 测试密码学原语空间开销　--->：", ret)

	time.Sleep(time.Hour * 2400)
}

// gin.Context几乎包含了http请求中的几乎所有信息
// 看起来gin.Context纯纯是和client交互用的，这部分代码无需改动
func test(contex *gin.Context) {
	var requestInfo map[string]interface{}
	body := contex.Request.Body
	bodyBytes, _ := ioutil.ReadAll(body)
	err := json.Unmarshal(bodyBytes, &requestInfo)
	if err != nil {
		contex.JSON(101, gin.H{
			"data": nil,
			"msg":  "json unmarshal error " + err.Error(),
		})
		return
	}

	// 接收客户端传来的参数，作为链码函数的参数
	amount := requestInfo["id"].(string)

	//payload, err := sdk.TestInvoke(fabSDK, &request, amount) // 调用函数
	payload := mockInvokeChaincode(amount)

	if err != nil {
		contex.JSON(102, gin.H{
			"data":    nil,
			"message": err.Error(),
		})
	} else {
		contex.JSON(200, gin.H{
			"data": string(payload),
			"msg":  "succeed",
		})
	}
}

func mockInvokeChaincode(amount string) []byte {
	fmt.Println("amount:", amount)
	return []byte("测试虚拟后端！")
}

//(orgPkSk sdkInit.OrgPkSk, txSpe sdkInit.TxSpecification, orgNum int, hashValue string, timeLock1 int64, value int64, spenderIdx int, receiverIdx int, channelIdx int, txKey string)
func lock(contex *gin.Context) {
	fmt.Println(fmt.Sprintf("Lock开始时间：%vms", time.Now().UnixNano()/ 1e6 ))
	var requestInfo map[string]interface{}
	body := contex.Request.Body
	bodyBytes, _ := ioutil.ReadAll(body)
	err := json.Unmarshal(bodyBytes, &requestInfo)
	if err != nil {
		contex.JSON(101, gin.H{
			"data": nil,
			"msg":  "json unmarshal error " + err.Error(),
		})
		return
	}

	// 接收客户端传来的参数，作为链码函数的参数

	hashValue := requestInfo["hashValue"].(string) // 其是原像还是哈希值取决于flag
	timeLockString := requestInfo["timeLock"].(string)
	timeLock, err := strconv.ParseInt(timeLockString, 10, 64)
	valueString := requestInfo["value"].(string)
	value, err := strconv.ParseInt(valueString, 10, 64)
	txKey := requestInfo["txKey"].(string)
	flag := requestInfo["flag"].(string)

	spenderIdxString := requestInfo["spenderIdx"].(string)
	spenderIdx, err := strconv.Atoi(spenderIdxString)
	receiverIdxString := requestInfo["receiverIdx"].(string)
	receiverIdx, err := strconv.Atoi(receiverIdxString)

	txSpe := createTxSpe(spenderIdx, receiverIdx, value)
	// 将txKey添加到公共账本
	privateLedger.txKeyList = append(privateLedger.txKeyList, txKey)
	// 将txSpe添加到公共账本
	var channelIdx int
	if flag=="hashValue" { // 后锁定的
		//privateLedger.txSpe2List = append(privateLedger.txSpe2List, txSpe)
		//privateLedger.txSpe2Map[txKey] = txSpe
		privateLedger.txSpe2Map.writeMap(txKey, txSpe)
		channelIdx = 1
	} else if flag=="preimage"{ // 先锁定的
		//privateLedger.txSpe1List = append(privateLedger.txSpe1List, txSpe)
		//privateLedger.txSpe1Map[txKey] = txSpe
		privateLedger.txSpe1Map.writeMap(txKey, txSpe)
		channelIdx = 0
	}

	id := Lock(privateLedger.orgPkSk, txSpe, privateLedger.orgNum, hashValue, timeLock, value, spenderIdx, receiverIdx, channelIdx, txKey, flag)
	if err != nil {
		contex.JSON(102, gin.H{
			"data":    nil,
			"message": err.Error(),
		})
	} else {
		contex.JSON(200, gin.H{
			"data": string(id),
			"msg":  "succeed",
		})
	}

}

func Hash(preImage string) string {
	sha256Passwd := sha256.Sum256([]byte(preImage))
	return hex.EncodeToString(sha256Passwd[:])
}

//arg:=[]string{"withdraw", preImage, id2, txKey}
func withdraw(contex *gin.Context) {
	fmt.Println(fmt.Sprintf("Withdraw开始时间：%vms", time.Now().UnixNano()/ 1e6 ))
	var requestInfo map[string]interface{}
	body := contex.Request.Body
	bodyBytes, _ := ioutil.ReadAll(body)
	err := json.Unmarshal(bodyBytes, &requestInfo)
	if err != nil {
		contex.JSON(101, gin.H{
			"data": nil,
			"msg":  "json unmarshal error " + err.Error(),
		})
		return
	}

	// 接收客户端传来的参数，作为链码函数的参数
	preImage := requestInfo["preImage"].(string)
	id := requestInfo["id"].(string)
	txKey := requestInfo["txKey"].(string)
	channel_idxString := requestInfo["channel_idx"].(string)
	channel_idx, err := strconv.Atoi(channel_idxString)
	org_idxString := requestInfo["org_idx"].(string)
	org_idx, err := strconv.Atoi(org_idxString)

	//fmt.Println("资产解锁输入参数：")
	//fmt.Println("channel:", channel_idx)
	//fmt.Println("hashValue:", preImage)
	//fmt.Println("计算出的hash：", Hash(preImage))

	//payload, err := sdk.TestInvoke(fabSDK, &request, amount) // 调用函数
	ret := Withdraw(preImage, id, txKey, channel_idx, org_idx)

	if err != nil {
		contex.JSON(102, gin.H{
			"data":    nil,
			"message": err.Error(),
		})
	} else {
		contex.JSON(200, gin.H{
			"data": strconv.FormatBool(ret),
			"msg":  "succeed",
		})
	}
}

//Audit(orgPkSk, orgNum, txSpe.R, spenderIdx1, receiverIdx1, asset1[0]-value1, value1, 0, txKey)
func audit(contex *gin.Context) {
	fmt.Println(fmt.Sprintf("Aduit开始时间：%vms", time.Now().UnixNano()/ 1e6 ))
	var requestInfo map[string]interface{}
	body := contex.Request.Body
	bodyBytes, _ := ioutil.ReadAll(body)
	err := json.Unmarshal(bodyBytes, &requestInfo)
	if err != nil {
		contex.JSON(101, gin.H{
			"data": nil,
			"msg":  "json unmarshal error " + err.Error(),
		})
		return
	}

	spenderIdxString := requestInfo["spenderIdx"].(string)
	spenderIdx, err := strconv.Atoi(spenderIdxString)
	receiverIdxString := requestInfo["receiverIdx"].(string)
	receiverIdx, err := strconv.Atoi(receiverIdxString)
	valueString := requestInfo["value"].(string)
	value, err := strconv.ParseInt(valueString, 10, 64)
	txKey := requestInfo["txKey"].(string)
	balanceString := requestInfo["balance"].(string)
	balance, err := strconv.ParseInt(balanceString, 10, 64)
	channelIdxString := requestInfo["channelIdx"].(string)
	channelIdx, err := strconv.Atoi(channelIdxString)

	//tmpIdx, _ := strconv.Atoi(txKey)
	if channelIdx==0{
		//txSpe := privateLedger.txSpe1List[tmpIdx-1]
		//txSpe := privateLedger.txSpe1Map[txKey]
		txSpe, ok := privateLedger.txSpe1Map.readMap(txKey)
		if ok!=true{
			fmt.Println("Map中找不到", txKey)
			os.Exit(-1)
		}
		Audit(privateLedger.orgPkSk, privateLedger.orgNum, txSpe.R, spenderIdx, receiverIdx, balance, value, channelIdx, txKey)
	}else if channelIdx==1{
		//txSpe := privateLedger.txSpe2List[tmpIdx-1]
		//txSpe := privateLedger.txSpe2Map[txKey]
		txSpe, ok := privateLedger.txSpe2Map.readMap(txKey)
		if ok!=true{
			fmt.Println("Map中找不到", txKey)
			os.Exit(-1)
		}
		Audit(privateLedger.orgPkSk, privateLedger.orgNum, txSpe.R, spenderIdx, receiverIdx, balance, value, channelIdx, txKey)
	}

	if err != nil {
		contex.JSON(102, gin.H{
			"data":    nil,
			"message": err.Error(),
		})
	} else {
		contex.JSON(200, gin.H{
			"data": "触发监管！",
			"msg":  "succeed",
		})
	}
}

//VerifyTwo(receiverIdx int, txKey string, channel_idx, org_idx int)
func verifytwo(contex *gin.Context) {
	fmt.Println(fmt.Sprintf("Verifytwo开始时间：%vms", time.Now().UnixNano()/ 1e6 ))
	var requestInfo map[string]interface{}
	body := contex.Request.Body
	bodyBytes, _ := ioutil.ReadAll(body)
	err := json.Unmarshal(bodyBytes, &requestInfo)
	if err != nil {
		contex.JSON(101, gin.H{
			"data": nil,
			"msg":  "json unmarshal error " + err.Error(),
		})
		return
	}

	receiverIdxString := requestInfo["receiverIdx"].(string)
	receiverIdx, err := strconv.Atoi(receiverIdxString)
	txKey := requestInfo["txKey"].(string)
	channel_idxString := requestInfo["channel_idx"].(string)
	channel_idx, err := strconv.Atoi(channel_idxString)
	org_idxString := requestInfo["org_idx"].(string)
	org_idx, err := strconv.Atoi(org_idxString)

	VerifyTwo(receiverIdx, txKey, channel_idx, org_idx) // Org2验证chain1的证明

	if err != nil {
		contex.JSON(102, gin.H{
			"data":    nil,
			"message": err.Error(),
		})
	} else {
		contex.JSON(200, gin.H{
			"data": "监管验证",
			"msg":  "succeed",
		})
	}
}

func verifytwoall(contex *gin.Context) {
	fmt.Println(fmt.Sprintf("Verifytwo开始时间：%vms", time.Now().UnixNano()/ 1e6 ))
	var requestInfo map[string]interface{}
	body := contex.Request.Body
	bodyBytes, _ := ioutil.ReadAll(body)
	err := json.Unmarshal(bodyBytes, &requestInfo)
	if err != nil {
		contex.JSON(101, gin.H{
			"data": nil,
			"msg":  "json unmarshal error " + err.Error(),
		})
		return
	}

	receiverIdxString := requestInfo["receiverIdx"].(string)
	receiverIdx, err := strconv.Atoi(receiverIdxString)
	txKey := requestInfo["txKey"].(string)
	channel_idxString := requestInfo["channel_idx"].(string)
	channel_idx, err := strconv.Atoi(channel_idxString)

	VerifyTwoAll(receiverIdx, txKey, channel_idx) // Org2验证chain1的证明

	if err != nil {
		contex.JSON(102, gin.H{
			"data":    nil,
			"message": err.Error(),
		})
	} else {
		contex.JSON(200, gin.H{
			"data": "监管验证",
			"msg":  "succeed",
		})
	}
}
