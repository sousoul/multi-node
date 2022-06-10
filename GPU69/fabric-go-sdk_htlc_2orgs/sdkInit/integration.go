package sdkInit

import (
	"encoding/hex"
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/event"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/status"
	contextAPI "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	fabAPI "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	contextImpl "github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/events/deliverclient/seek"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"log"

	"time"
	//"github.com/hyperledger/fabric-protos-go/peer"
	//"github.com/golang/protobuf/proto"
)

func DiscoverLocalPeers(ctxProvider contextAPI.ClientProvider, expectedPeers int) ([]fabAPI.Peer, error) {
	ctx, err := contextImpl.NewLocal(ctxProvider)
	if err != nil {
		return nil, fmt.Errorf("error creating local context: %v", err)
	}

	discoveredPeers, err := retry.NewInvoker(retry.New(retry.TestRetryOpts)).Invoke(
		func() (interface{}, error) {
			peers, serviceErr := ctx.LocalDiscoveryService().GetPeers()
			if serviceErr != nil {
				return nil, fmt.Errorf("getting peers for MSP [%s] error: %v", ctx.Identifier().MSPID, serviceErr)
			}
			if len(peers) < expectedPeers {
				return nil, status.New(status.TestStatus, status.GenericTransient.ToInt32(), fmt.Sprintf("Expecting %d peers but got %d", expectedPeers, len(peers)), nil)
			}
			return peers, nil
		},
	)
	if err != nil {
		return nil, err
	}

	return discoveredPeers.([]fabAPI.Peer), nil
}
//func (t *SdkEnvInfo)InitService(chaincodeID, channelID string, org *OrgInfo, sdk *fabsdk.FabricSDK) error{
func (t *SdkEnvInfo)InitService(chaincodeID, channelID string, org *OrgInfo, sdk *fabsdk.FabricSDK) (*channel.Client, error){
	handler := &SdkEnvInfo{
		ChaincodeID:chaincodeID,
	}
	//prepare channel client context using client context
	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser(org.OrgUser), fabsdk.WithOrg(org.OrgName))
	// Channel client is used to query and execute transactions (Org1 is default org)
	var err error
	//t.Client,err= channel.New(clientChannelContext)
	//t.Client[0],err= channel.New(clientChannelContext)  // index out of range [0] with length 0
	var new_client *channel.Client
	new_client, err = channel.New(clientChannelContext) // 创建组织org在通道channelID上的客户端
	//t.Client[len(t.Client)-1][len(t.Client[len(t.Client)-1])-1] = new_client
	if err != nil {
		fmt.Println("创建通道客户端失败")
		//return nil // 这里源代码应该写错了
		return new_client, err
	}
	handler.Client = t.Client
	return new_client, nil
}

func regitserEvent(client *channel.Client, chaincodeID, eventID string) (fabAPI.Registration, <-chan *fabAPI.CCEvent) {

	reg, notifier, err := client.RegisterChaincodeEvent(chaincodeID, eventID)
	if err != nil {
		fmt.Println("注册链码事件失败: %s", err)
	}
	return reg, notifier
}

func eventResult(notifier <-chan *fabAPI.CCEvent, eventID string) error {
	select {
	case ccEvent := <-notifier:
		fmt.Printf("接收到链码事件: %v\n", ccEvent)
	case <-time.After(time.Second * 20):
		return fmt.Errorf("不能根据指定的事件ID接收到相应的链码事件(%s)", eventID)
	}
	return nil
}

// 改了几个地方
func chainCodeEventListener(c *channel.Client, ec *event.Client, chaincodeID string) fabAPI.Registration {
	eventName := ".*"
	log.Printf("Listen chaincode event: %v", eventName)

	var (
		ccReg   fabAPI.Registration
		eventCh <-chan *fabAPI.CCEvent
		err     error
	)
	if c != nil {
		log.Println("Using client to register chaincode event")
		ccReg, eventCh, err = c.RegisterChaincodeEvent(chaincodeID, eventName)
	} else {
		log.Println("Using event client to register chaincode event")
		ccReg, eventCh, err = ec.RegisterChaincodeEvent(chaincodeID, eventName)
	}
	if err != nil {
		log.Printf("Register chaincode event error: %v", err.Error())
		return nil
	}

	// consume event
	go func() {
		for e := range eventCh {
			log.Printf("Receive cc event, ccid: %v \neventName: %v\n"+
				"payload: %v \ntxid: %v \nblock: %v \nsourceURL: %v\n",
				e.ChaincodeID, e.EventName, string(e.Payload), e.TxID, e.BlockNumber, e.SourceURL)
		}
	}()

	return ccReg
}

// 链码事件
func (t *SdkEnvInfo)Listen_chaincode_event(chaincodeID, channelID string, org *OrgInfo, sdk *fabsdk.FabricSDK) (fabAPI.Registration, *event.Client){
	//prepare channel client context using client context
	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser(org.OrgUser), fabsdk.WithOrg(org.OrgName))
	// 创建对应的事件客户端event client
	ec, err := event.New(
		clientChannelContext,
		event.WithBlockEvents(),
		event.WithSeekType(seek.Newest)) // 这里的option可参考https://lessisbetter.site/2019/11/13/using-fabric-sdk-go-register-event/#%E7%A4%BA%E4%BE%8B%E9%A1%B9%E7%9B%AE
	if err != nil {
		panic(err)
	}
	// chaincode event listen
	//defer ec.Unregister(chainCodeEventListener(nil, ec, chaincodeID)) // 不清楚为何这样订阅不到链码事件，应该是事件通道eventCh还没来得及从链码接收到事件，就被注销关闭了，因为把注销放在main()中最后就可以订阅到链码事件
	reg := chainCodeEventListener(nil, ec, chaincodeID)
	//_ = reg
	//defer ec.Unregister(reg)

	return reg, ec
}


func BlockListener(ec *event.Client) fabAPI.Registration {
	// Register monitor block event
	beReg, beCh, err := ec.RegisterBlockEvent()
	if err != nil {
		log.Printf("Register block event error: %v", err)
	}
	log.Println("Registered block event")

	// Receive block event
	go func() {
		for e := range beCh {
			log.Printf("Receive block event:\nSourceURL: %v\nNumber: %v\nHash"+
				": %v\nPreviousHash: %v\nBlock data: \n",
				e.SourceURL,
				e.Block.Header.Number,
				hex.EncodeToString(e.Block.Header.DataHash),
				hex.EncodeToString(e.Block.Header.PreviousHash))
			fmt.Println("<---------------------打印整个block--------------------->")
			//log.Println(string(e.Block.Data.Data[0]))
			log.Println(e)
		}
	}()

	return beReg
}

// 输出太乱
//func FilteredBlockListener(ec *event.Client) fabAPI.Registration {
//	// Register monitor filtered block event
//	fbeReg, fbeCh, err := ec.RegisterFilteredBlockEvent()
//	if err != nil {
//		log.Printf("Register filtered block event error: %v", err)
//	}
//	log.Println("Registered filtered block event")
//
//	// Receive filtered block event
//	go func() {
//		for e := range fbeCh {
//			log.Printf("<===Receive filterd block event:===>\nNumber: %v\nChannelID: %v\nlen("+
//				"transactions): %v\nSourceURL: %v",
//				e.FilteredBlock.Number, e.FilteredBlock.ChannelId, len(e.FilteredBlock.
//					FilteredTransactions), e.SourceURL)
//			for i, tx := range e.FilteredBlock.FilteredTransactions {
//				log.Printf("tx index: %d\n " +
//					"type: %v\n " +
//					"txid: %v\n "+
//					"validation code: %v\n", i,
//					tx.Type, tx.Txid,
//					tx.TxValidationCode,
//				)
//				payload := string(tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().Payload)
//				eventname := string(tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().EventName)
//				//_ = payload
//				fmt.Println("eventname:", eventname)
//				fmt.Println("payload:", payload)
//				fmt.Println("长度:", len(tx.GetTransactionActions().ChaincodeActions))
//			}
//
//			log.Println("<==========END==========>")
//			//log.Println() // Just go print empty log for easy to read
//		}
//	}()
//	return fbeReg
//}

// 打印详细信息版本
func FilteredBlockListener(ec *event.Client, listenerTag string) fabAPI.Registration {
	// Register monitor filtered block event
	fbeReg, fbeCh, err := ec.RegisterFilteredBlockEvent()
	if err != nil {
		log.Printf(listenerTag+"Register filtered block event error: %v", err)
	}
	log.Println(listenerTag+"Registered filtered block event")

	// Receive filtered block event
	go func() {
		for e := range fbeCh {
			log.Printf("<============%vReceive filterd block event:============>\n" +
				"Number: %v\nChannelID: %v\nlen(transactions): %v\nSourceURL: %v",
				listenerTag, e.FilteredBlock.Number, e.FilteredBlock.ChannelId, len(e.FilteredBlock.
					FilteredTransactions), e.SourceURL)
			for i, tx := range e.FilteredBlock.FilteredTransactions {
				//payload := string(tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().Payload)
				eventname := string(tx.GetTransactionActions().ChaincodeActions[0].GetChaincodeEvent().EventName)
				//fmt.Println("eventname:", eventname)
				//fmt.Println("payload:", payload)
				//fmt.Println("长度:", len(tx.GetTransactionActions().ChaincodeActions))

				log.Printf("<======Block%v中的Tx%d:======>",e.FilteredBlock.Number, i)
				fmt.Printf(" tx index: %d\n type: %v\n txid: %v\n validation code: %v\n event name: %v\n",
					i, tx.Type, tx.Txid, tx.TxValidationCode, eventname)
			}
			log.Println("<============END============>")
		}
	}()
	return fbeReg
}

func CreateEventClient(channelID string, org *OrgInfo, sdk *fabsdk.FabricSDK) *event.Client {
	clientChannelContext := sdk.ChannelContext(channelID, fabsdk.WithUser(org.OrgUser), fabsdk.WithOrg(org.OrgName))
	// 创建对应的事件客户端event client
	ec, err := event.New(
		clientChannelContext,
		event.WithBlockEvents(), // 如果没有，会是filtered，因此如果创建filteredblockevent，这一行需要注释才有意义
		// event.WithBlockNum(1), // 从指定区块获取，需要此参数
		event.WithSeekType(seek.Newest)) // 这里的option可参考https://lessisbetter.site/2019/11/13/using-fabric-sdk-go-register-event/#%E7%A4%BA%E4%BE%8B%E9%A1%B9%E7%9B%AE
	if err != nil {
		panic(err)
	}
	return ec
}