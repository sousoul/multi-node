# multi-node
本仓库将可信交易构件代码部署在三台服务器上，并通过开源工具Locust进行交易吞吐率测试。Locust通过分析 HTTP 请求的吞吐率实现对系统性能的评估。Locust 可模拟多个用户，并支持自定义任务;模拟的用户通过并发地执行任务，来和待测系统交互。

三台服务器的IP如下表格所示：

| 服务器   | GPU68               | GPU69                                         | GPU74                                         | GPU75        |
| -------- | ------------------- | --------------------------------------------- | --------------------------------------------- | ------------ |
| IP地址   | 10.200.5.121        | 10.200.5.122                                  | 10.200.5.127                                  | 10.200.5.128 |
| 节点容器 | orderer.example.com | peer0.org1.example.com peer1.org1.example.com | peer0.org2.example.com peer1.org2.example.com |              |

其中在GPU68上部署排序节点orderer.example.com，在GPU69上部署组织1的两个节点peer0.org1.example.com和peer1.org1.example.com，在GPU74上部署组织2的两个节点peer0.org2.example.com和peer1.org2.example.com，在GPU75上运行Locust测试脚本。

## 1. 代码使用

#### 1.1 在4台服务器上克隆仓库，并进入对应的目录。

以GPU68为例，进入GPU68的目录。

```
git clone git@github.com:sousoul/multi-node.git
cd multi-node/GPU68/fabric-go-sdk_htlc_2orgs/ 
```
#### 1.2 启动节点容器

在GPU68，GPU69，GPU74三台服务器上，运行以下命令启动对应的节点容器

```
./restart_network.sh
```

#### 1.3 运行SDK

在GPU69上，运行以下命令来运行SDK，完成网络的搭建。在本仓库中搭建了上方表格中所示的区块链网络，共包括组织1，组织2两个组织。

```
./fabric-go-sdk
```

#### 1.4 运行locust

在GPU75上，运行以下命令。

```
cd multi-node/GPU75/LocustTest/
locust
```

#### 1.5 设置测试参数

在浏览器中打开http://10.200.5.128:8089/

按下图配置参数，

<img width="336" alt="image" src="https://user-images.githubusercontent.com/49592082/173161718-3c26799c-abe4-4d61-a2c2-a3a20eff4ebc.png">

并点击Start swarming开始测试。


