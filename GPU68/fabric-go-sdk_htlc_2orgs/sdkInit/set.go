package sdkInit

import (
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
)

//func (t *Application) Set(args []string) (string, error) {
//	var tempArgs [][]byte
//	for i := 1; i < len(args); i++ {
//		tempArgs = append(tempArgs, []byte(args[i]))
//	}
//
//	//request := channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args: [][]byte{[]byte(args[1]), []byte(args[2])}}
//	request := channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args: tempArgs} //
//
//	//response, err := t.SdkEnvInfo.Client.Execute(request)
//	//response, err := t.SdkEnvInfo.Client[0].Execute(request)
//	//response, err := t.SdkEnvInfo.Client[0][0].Execute(request)
//	response, err := t.SdkEnvInfo.Client[1][0].Execute(request) // 测试org1调用mychannel2上的链码
//	if err != nil {
//		// 资产转移失败
//		//return "", err
//		return "链码函数调用发生错误：", err
//	}
//
//	//fmt.Println("============== response:",response)
//
//	//return string(response.TransactionID), nil
//	return string(response.Payload), nil
//}

// 调用组织org_idx在通道channel_idx上的链码
func (t *Application) Set(args []string, channel_idx int, org_idx int) (string, error) {
	var tempArgs [][]byte
	for i := 1; i < len(args); i++ {
		tempArgs = append(tempArgs, []byte(args[i]))
	}

	//request := channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args: [][]byte{[]byte(args[1]), []byte(args[2])}}
	request := channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args: tempArgs} //


	targetPeers := fmt.Sprintf("peer0.org%d.example.com", org_idx+1) // 每次都是peer0执行链码
	//reqPeers := channel.WithTargetEndpoints("peer0.org2.example.com")
	reqPeers := channel.WithTargetEndpoints(targetPeers)

	//response, err := t.SdkEnvInfo.Client.Execute(request)
	//response, err := t.SdkEnvInfo.Client[0].Execute(request)
	//response, err := t.SdkEnvInfo.Client[0][0].Execute(request)
	//response, err := t.SdkEnvInfo.Client[channel_idx][org_idx].Execute(request) // 测试org1调用mychannel2上的链码

	response, err := t.SdkEnvInfo.Client[channel_idx][org_idx].Execute(request, reqPeers) // 指定节点执行链码



	if err != nil {
		// 资产转移失败
		//return "", err
		return "链码函数调用发生错误：", err
	}

	//fmt.Println("============== response:",response)

	//return string(response.TransactionID), nil
	//fmt.Println("调用的函数：", args[0], "对应的txid：", response.TransactionID)
	return string(response.Payload), nil
}