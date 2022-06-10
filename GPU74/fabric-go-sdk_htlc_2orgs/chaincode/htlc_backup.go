package main


//import (
//	"crypto/sha256"
//	"encoding/hex"
//)
//
//// 先用账户的形式，检验HTLC的原子性是否能保障
//// 然后再迁移到二维账本
//
//type Account struct {
//	Amount   uint64 `json:"amount"`
//	H   string `json:"passwd"`
//}
//
//////preimageBytesHex := "0x726f6f74726f6f74"
////hashLock := "0242c0436daa4c241ca8a793764b7dfb50c223121bb844cf49be670a3af4dd18"
////preImage := "rootroot"
//// Hash(preImage) 计算哈希值
//func Hash(preImage string) string {
//	sha256Passwd := sha256.Sum256([]byte(preImage))
//	return hex.EncodeToString(sha256Passwd[:])
//}
//
//func createMidAccount(flag string, hashValueOrPreimage string)  Account{
//	mid := Account{}
//	// 用flag区分传入的hashValueOrPreimage是哈希值还是原像，无论哪种情况，mid.H都是哈希值
//	if flag == "hash" {
//		mid.H = hashValueOrPreimage // hashValueOrPreimage == Hash_value
//	} else if flag == "preimage" {
//		mid.H = Hash(hashValueOrPreimage) // hashValueOrPreimage == preimage
//	}
//	return mid
//}
//
//func createHash(args []string)  {
//	sender := args[0]
//	receiver := args[1]
//	amountStr := args[2]
//	timeLockStr := args[3]
//	hashValue := args[4] // 哈希时间锁的哈希值
//	passwd := args[5] // 加锁方的原像
//	midaddress := args[6]
//
//	transfer(sender, midaddress, amountStr, passwd) // sender向中间账户转账
//
//	// 将sender, receiver等变量保存到本条链的数据库中；对方领取资产的时候需要读取这些变量
//}
//
//func withdraw(h string)  {
//	// 先调用withdraw()的一方，通过参数传入原像h；后调用withdraw()的一方，需要从本条链的数据库中读取先调用withdraw的一方保存的原像h
//
//	// 从本条链的数据库中读取createHash()中保存的变量midaddress, receiver, amountStr
//
//	// createHash和withdraw分别由交易的双方执行，并通过HTLC结构体共享调用transfer函数需要的参数
//	transfer(midaddress, receiver, amountStr, h) // 中间账户向receiver转账
//
//	// 先调用withdraw的一方，领取资产后，将原像保存到本条链的数据库
//}
//
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
//
//// 用户from向用户to转账amount金额，h是用户from的原像
//func transfer(from Account, to Account, amount string,  h string)  {
//	if Hash(h) != from.H{ // 原像h不对，函数调用者没有权限转账
//		return
//	}
//	// 账户：
//	from.Amount -= amount
//	to.Amount += amount
//	// 二维账本：
//	// from是支出方，创建一笔交易并记录到二维账本上
//}
//
//// testWF()相当于testWF.ts，测试一次跨链
//func testWF() {
//	// 资产兑换账户
//	Alice := Account{}
//	Bob := Account{}
//
//	// 哈西时间锁参数
//	T1 := "100" // 时间锁1
//	T2 := "50" // 时间锁2
//	var Hash_value string // 哈希值，加锁时用
//	var preimage string// 哈希原像，解锁时用；Hash_value = Hash(preimage)
//
//	var Alice_preimage string // Alice自己持有
//	var Bob_preimage string // Bob自己持有
//
//	mid1 := createMidAccount("preimage", preimage)// Alice在chain_1上创建中间账户mid1
//	mid2 := createMidAccount("hash", Hash_value)// Bob在chain_2上创建中间账户mid2
//
//	createHash("Alice", "Bob", "2", T1, Hash_value, Alice_preimage, "mid1") // Alice锁定资产
//	createHash("Bob", "Alice", "1", T2, Hash_value, Bob_preimage, "mid2") // Bob锁定资产
//
//	withdraw(preimage) // Alice取走Bob在chain_2锁定的资产
//	// 感觉还需要在withdraw中设置一个flag来区分调用者
//	withdraw(preimage) // Bob取走Alice在chain_1锁定的资产
//
//}