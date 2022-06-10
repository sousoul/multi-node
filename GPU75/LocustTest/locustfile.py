from locust import HttpUser, task
import json
import random
from locust import TaskSet, task, constant_throughput
import queue
import time
# locust -t 10s --autostart # With this command, you can start stress testing directly without open the browser.

txNum = 2000 # Number of cross-chain transactions
value1 = 1 # Transaction amount, user1 transfer value1 to User2 on chain1.
value2 = 1 # Transaction amount, user2 transfer value2 to User1 on chain2.

orgNum = 2
Asset1 = []
Asset2 = []
# Initialize balance, the values need to be consist with which are set in SDK.
for i in range(orgNum):
    Asset1.append(10000000)
    Asset2.append(10000000)

hashLock = "0242c0436daa4c241ca8a793764b7dfb50c223121bb844cf49be670a3af4dd18"
preImage = "rootroot"

def LockAsset(user, timeLock, value, txKey, flag, spenderIdx, receiverIdx):
    if flag == "hashValue":
        res = user.client.post("/htlc/lock", json={
            "hashValue": hashLock,
            "timeLock": str(timeLock),
            "value": str(value),
            "txKey": str(txKey),
            "flag": flag,
            "spenderIdx": str(spenderIdx),
            "receiverIdx": str(receiverIdx)
        }, name = "Lock asset on chain2")
    else:
        res = user.client.post("/htlc/lock", json={
            "hashValue": preImage,
            "timeLock": str(timeLock),
            "value": str(value),
            "txKey": str(txKey),
            "flag": flag,
            "spenderIdx": str(spenderIdx),
            "receiverIdx": str(receiverIdx)
        }, name = "Lock asset on chain1")
    return res.json()["data"]

def WithdrawAsset(user, preImage, id, txKey, channel_idx, org_idx):
    # res = user.client.post("/htlc/withdraw", json={
    #     "preImage": preImage,
    #     "id": id,
    #     "txKey": str(txKey),
    #     "channel_idx": str(channel_idx),
    #     "org_idx": str(org_idx),
    # })
    if channel_idx==1:
        res = user.client.post("/htlc/withdraw", json={
            "preImage": preImage,
            "id": id,
            "txKey": str(txKey),
            "channel_idx": str(channel_idx),
            "org_idx": str(org_idx),
        }, name = "Withdraw asset on chain2")

    elif channel_idx==0:
        res = user.client.post("/htlc/withdraw", json={
            "preImage": preImage,
            "id": id,
            "txKey": str(txKey),
            "channel_idx": str(channel_idx),
            "org_idx": str(org_idx),
        }, name = "Withdraw asset on chain1")

def Audit(user, balance, value, txKey, channelIdx, spenderIdx, receiverIdx):
    print("Auditing", str(txKey), str(balance))
    # res = user.client.post("/htlc/audit", json={
    #     "balance": str(balance),
    #     "value": str(value),
    #     "txKey": str(txKey),
    #     "channelIdx": str(channelIdx),
    #     "spenderIdx": str(spenderIdx),
    #     "receiverIdx": str(receiverIdx)
    # })
    if channelIdx==0:
        res = user.client.post("/htlc/audit", json={
            "balance": str(balance),
            "value": str(value),
            "txKey": str(txKey),
            "channelIdx": str(channelIdx),
            "spenderIdx": str(spenderIdx),
            "receiverIdx": str(receiverIdx)
        }, name = "Compute proof on chain1")

    elif channelIdx==1:
        res = user.client.post("/htlc/audit", json={
            "balance": str(balance),
            "value": str(value),
            "txKey": str(txKey),
            "channelIdx": str(channelIdx),
            "spenderIdx": str(spenderIdx),
            "receiverIdx": str(receiverIdx)
        }, name = "Compute proof on chain2")

def VerifyTwo(user, txKey, channel_idx, org_idx, receiverIdx):
    # res = user.client.post("/htlc/verifytwo", json={
    #     "txKey": str(txKey),
    #     "channel_idx": str(channel_idx),
    #     "org_idx": str(org_idx),
    #     "receiverIdx": str(receiverIdx)
    # })
    if channel_idx==0:
        res = user.client.post("/htlc/verifytwo", json={
            "txKey": str(txKey),
            "channel_idx": str(channel_idx),
            "org_idx": str(org_idx),
            "receiverIdx": str(receiverIdx)
        }, name = "Verify proof on chain1")

    elif channel_idx==1:
        res = user.client.post("/htlc/verifytwo", json={
            "txKey": str(txKey),
            "channel_idx": str(channel_idx),
            "org_idx": str(org_idx),
            "receiverIdx": str(receiverIdx)
        }, name = "Verify proof on chain2")

def test_register(user):
    # 1. Get the data for test.
    try:
        data = user.user_data_queue.get()
    except queue.Empty:
        print('data run out, test ended.')
        exit(0)

    txKey = data['txKey']

    # 2. Start Test
    # 2.1 Transaction process.
    if data['type']=="HTLC":
        print('Cross-chain tx: {}'.format(txKey))
        id1 = LockAsset(user=user, timeLock=1000+2*txKey, value=value1, txKey=txKey, flag="preimage", spenderIdx=0, receiverIdx=1)
        id2 = LockAsset(user=user, timeLock=500+txKey, value=value2, txKey=txKey, flag="hashValue", spenderIdx=1, receiverIdx=0)

        WithdrawAsset(user=user, preImage=preImage, id=id2, txKey=txKey, channel_idx=1, org_idx=0)
        WithdrawAsset(user=user, preImage=preImage, id=id1, txKey=txKey, channel_idx=0, org_idx=1)
    # 2.2 Audit the previous txNum transactions in turn.
    elif data['type']=="Audit":
        for txI in range(1, txNum+1):
            print("Audit the {}th cross-chain tx".format(txI))
            # For the sake of simplicity，the transaction amount is set as value1 and value2.
            Audit(user=user, balance=Asset1[0]-value1*txI, value=value1, txKey=txI, channelIdx=0, spenderIdx=0, receiverIdx=1) # chain1
            Audit(user=user, balance=Asset2[1]-value2*txI, value=value2, txKey=txI, channelIdx=1, spenderIdx=1, receiverIdx=0) # chain2
            VerifyTwo(user=user, txKey=txI, channel_idx=0, org_idx=1, receiverIdx=1) # chain1
            VerifyTwo(user=user, txKey=txI, channel_idx=1, org_idx=0, receiverIdx=0) # chain2

class WebsiteUser(HttpUser):
    host = "http://10.200.5.122:9192" #
    tasks = [test_register]
    # wait_time = constant_throughput(1)

    #  create data for test
    user_data_queue = queue.Queue()
    for index in range(1, txNum+1):
        data = {
            "txKey": index,
            "type": "HTLC",
            "value1": "pwd%04d" % index,
            "value2": "pwd%04d" % index,
        }
        user_data_queue.put_nowait(data)
    data = {
        "txKey": txNum+1,
        "type": "Audit",
    }
    user_data_queue.put_nowait(data)

    # min_wait = 1000
    # max_wait = 3000
