package sdkInit

import (
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
)

//func (t *Application) Get(args []string) (string, error) {
//	//response, err := t.SdkEnvInfo.Client.Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
//	//response, err := t.SdkEnvInfo.Client[0].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
//	//response, err := t.SdkEnvInfo.Client[0][0].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
//	response, err := t.SdkEnvInfo.Client[1][0].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
//	if err != nil {
//		return "", fmt.Errorf("failed to query: %v", err)
//	}
//
//	return string(response.Payload), nil
//}

// 调用组织org_idx在通道channel_idx上的链码
func (t *Application) Get(args []string, channel_idx int, org_idx int) (string, error) {

	targetPeers := fmt.Sprintf("peer0.org%d.example.com", org_idx+1) // 每次都是peer0执行链码
	//reqPeers := channel.WithTargetEndpoints("peer1.org1.example.com")
	reqPeers := channel.WithTargetEndpoints(targetPeers)

	//response, err := t.SdkEnvInfo.Client.Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
	//response, err := t.SdkEnvInfo.Client[0].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
	//response, err := t.SdkEnvInfo.Client[0][0].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
	//response, err := t.SdkEnvInfo.Client[channel_idx][org_idx].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:[][]byte{[]byte(args[1])}})
	var tempArgs [][]byte
	for i := 1; i < len(args); i++ {
		tempArgs = append(tempArgs, []byte(args[i]))
	}
	response, err := t.SdkEnvInfo.Client[channel_idx][org_idx].Query(channel.Request{ChaincodeID: t.SdkEnvInfo.ChaincodeID, Fcn: args[0], Args:tempArgs}, reqPeers)

	if err != nil {
		return "", fmt.Errorf("failed to query: %v", err)
	}

	return string(response.Payload), nil
}
