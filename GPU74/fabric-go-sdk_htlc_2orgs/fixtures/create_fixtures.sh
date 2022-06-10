# 生成组织的证书文件
cryptogen generate --config=crypto-config.yaml
# 生成通道配置文件
configtxgen -profile TwoOrgsOrdererGenesis -outputBlock  ./channel-artifacts/genesis.block -channelID fabric-channel  # 生成创世块
configtxgen -profile TwoOrgsChannel1 -outputCreateChannelTx  ./channel-artifacts/channel1.tx -channelID mychannel1 # 创建channel1.tx
configtxgen -profile TwoOrgsChannel2 -outputCreateChannelTx  ./channel-artifacts/channel2.tx -channelID mychannel2 # 创建channel2.tx
# org1
configtxgen -profile TwoOrgsChannel1 -outputAnchorPeersUpdate  ./channel-artifacts/Org1MSPanchors1.tx -channelID mychannel1 -asOrg Org1MSP # 为org1创建通道1上的锚节点文件
configtxgen -profile TwoOrgsChannel2 -outputAnchorPeersUpdate  ./channel-artifacts/Org1MSPanchors2.tx -channelID mychannel2 -asOrg Org1MSP # 为org1创建通道2上的锚节点文件
# org2
configtxgen -profile TwoOrgsChannel1 -outputAnchorPeersUpdate  ./channel-artifacts/Org2MSPanchors1.tx -channelID mychannel1 -asOrg Org2MSP # 为org2创建通道1上的锚节点文件
configtxgen -profile TwoOrgsChannel2 -outputAnchorPeersUpdate  ./channel-artifacts/Org2MSPanchors2.tx -channelID mychannel2 -asOrg Org2MSP # 为org2创建通道2上的锚节点文件
