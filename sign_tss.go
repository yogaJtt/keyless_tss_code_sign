package main

import (
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// func single_sign() {
// 	// 初始化BLS签名库
// 	err := bls.Init(bls.BLS12_381)
// 	if err != nil {
// 		fmt.Println("Error initializing BLS library:", err)
// 		return
// 	}

// 	// 生成公私钥对
// 	sk := bls.SecretKey{}
// 	sk.SetByCSPRNG()
// 	pk := sk.GetPublicKey()

// 	// 签名消息
// 	msg := []byte("hello, world!")
// 	sig := sk.SignByte(msg)

// 	// 验证签名
// 	valid := sig.VerifyByte(pk, msg)
// 	fmt.Println("Signature valid?", valid)
// }

// func agg_sign() {
// 	// 初始化BLS签名库
// 	err := bls.Init(bls.BLS12_381)
// 	if err != nil {
// 		fmt.Println("Error initializing BLS library:", err)
// 		return
// 	}

// 	// 生成私钥和公钥
// 	sk1 := bls.SecretKey{}
// 	sk1.SetByCSPRNG()
// 	pk1 := sk1.GetPublicKey()

// 	sk2 := bls.SecretKey{}
// 	sk2.SetByCSPRNG()
// 	pk2 := sk2.GetPublicKey()

// 	fmt.Println("私钥1", sk1)
// 	fmt.Println("公钥1", pk1)
// 	fmt.Println("私钥2", sk2)
// 	fmt.Println("公钥2", pk2)

// 	// 需要聚合的签名
// 	sig1 := sk1.Sign("hello")
// 	sig2 := sk2.Sign("hello") //这里因为没有对消息做hash,所以在最后聚合数据处消息数据的大小不一致，所以测试中还是采用一样的消息

// 	// 聚合签名
// 	aggSig := bls.Sign{}
// 	aggSig.Aggregate([]bls.Sign{*sig1, *sig2})
// 	// aggSig.Add(sig1)
// 	// aggSig.Add(sig2)

// 	// 聚合公钥
// 	aggPk := bls.PublicKey{}
// 	aggPk.Add(pk1)
// 	aggPk.Add(pk2)

// 	//验证聚合签名
// 	fmt.Println("aggSig verify result:", aggSig.Verify(&aggPk, "hello"))

// }

func init_bls() {
	//初始化 BLS 库
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		fmt.Println("error initializing bls library:", err)
		return
	}
}

func multi_sign() {
	init_bls()

	sk_init := bls.SecretKey{} //f = 3*x+6
	sk_init.SetLittleEndian([]byte{6})
	pk_init := sk_init.GetPublicKey()
	//生成三个私钥和对应的公钥
	sk1 := bls.SecretKey{}
	sk2 := bls.SecretKey{}
	sk3 := bls.SecretKey{}
	sk1.SetLittleEndian([]byte{9})
	sk2.SetLittleEndian([]byte{12})
	sk3.SetLittleEndian([]byte{15})
	pk1 := sk1.GetPublicKey()
	pk2 := sk2.GetPublicKey()
	pk3 := sk3.GetPublicKey()

	fmt.Println("原始私钥: ", sk_init.SerializeToHexStr())
	fmt.Println("原始公钥: ", pk_init.SerializeToHexStr())
	fmt.Println("分片私钥sk1: ", sk1.SerializeToHexStr())
	fmt.Println("分片公钥pk1: ", pk1.SerializeToHexStr())

	//签名消息
	msg := "hello, world!"

	sig1 := sk1.Sign(msg)
	sig2 := sk2.Sign(msg)
	sig3 := sk3.Sign(msg)

	//{1，2}-of-3聚合签名
	agg_sig_1_2 := bls.Sign{}
	agg_sig_1_2.Aggregate([]bls.Sign{*sig1, *sig2})
	agg_pubkey_1_2 := bls.PublicKey{}
	agg_pubkey_1_2.Add(pk1)
	agg_pubkey_1_2.Add(pk2)
	//验签
	fmt.Println("aggSig verify result:", agg_sig_1_2.Verify(&agg_pubkey_1_2, msg))
	fmt.Println("aggSig verify result:", agg_sig_1_2.Verify(pk_init, msg))

	//{1，3}-of-3聚合签名
	agg_sig_1_3 := bls.Sign{}
	agg_sig_1_3.Aggregate([]bls.Sign{*sig1, *sig3})
	agg_pubkey_1_3 := bls.PublicKey{}
	agg_pubkey_1_3.Add(pk1)
	agg_pubkey_1_3.Add(pk3)
	//验签
	fmt.Println("aggSig verify result:", agg_sig_1_3.Verify(&agg_pubkey_1_3, msg))

	//{2，3}-of-3聚合签名
	agg_sig_2_3 := bls.Sign{}
	agg_sig_2_3.Aggregate([]bls.Sign{*sig2, *sig3})
	agg_pubkey_2_3 := bls.PublicKey{}
	agg_pubkey_2_3.Add(pk2)
	agg_pubkey_2_3.Add(pk3)
	//验签
	fmt.Println("aggSig verify result:", agg_sig_2_3.Verify(&agg_pubkey_2_3, msg))

	//3-of-3聚合签名
	agg_sig_1_2_3 := bls.Sign{}
	agg_sig_1_2_3.Aggregate([]bls.Sign{*sig1, *sig2, *sig3})
	agg_pubkey_1_2_3 := bls.PublicKey{}
	agg_pubkey_1_2_3.Add(pk1)
	agg_pubkey_1_2_3.Add(pk2)
	agg_pubkey_1_2_3.Add(pk3)
	//验签
	fmt.Println("aggSig 123 verify result:", agg_sig_1_2_3.Verify(&agg_pubkey_1_2_3, msg))
	fmt.Println("aggSig 123 verify result:", agg_sig_1_2_3.Verify(pk_init, msg))

}

func get_keyshare() {
	init_bls()

	// 原始私钥
	sk := bls.SecretKey{}
	sk.SetLittleEndian([]byte{6})
	pk := sk.GetPublicKey()
	fmt.Println("原私钥：", sk.SerializeToHexStr())
	fmt.Println("原公钥：", pk.SerializeToHexStr())

	//构造多项式(系数)
	ask := make([]bls.SecretKey, 2)
	apk := make([]bls.PublicKey, 2)
	//第一个系数是6
	ask[0] = sk
	apk[0] = *pk
	//第二个系数是3
	ask[1].SetLittleEndian([]byte{3})
	apk[1] = *ask[1].GetPublicKey()
	// fmt.Println("私钥：", ask)
	// fmt.Println("公钥：", apk)

	//test:
	// id1 := &bls.ID{}
	// id1.SetLittleEndian([]byte{1})
	// share_sk1 := new(bls.SecretKey)
	// err := share_sk1.Set(ask, id1)
	// if err != nil {
	// 	// handle error
	// 	fmt.Println("error", err)
	// 	return
	// }
	// fmt.Println("share_sk1: ", share_sk1)

	//参与方从1-3循环
	id_list := make([]*bls.ID, 3)
	//keyshare的私钥数组
	share_sks := make([]bls.SecretKey, 3)
	//keyshare的公钥数组
	share_pks := make([]bls.PublicKey, 3)
	for i := 0; i < 3; i++ {
		id_i := &bls.ID{}
		id_i.SetLittleEndian([]byte{byte(i + 1)})
		id_list[i] = id_i
		err1 := share_sks[i].Set(ask, id_list[i])
		if err1 != nil {
			// handle error
			fmt.Println("error", err1)
			return
		}

		err2 := share_pks[i].Set(apk, id_list[i])
		if err2 != nil {
			// handle error
			fmt.Println("error", err2)
			return
		}

	}
	// fmt.Println("share_sk1: ", share_sks[0])
	// fmt.Println("share_pk1: ", share_pks[0])

	fmt.Println("分片私钥share_sk1: ", share_sks[0].SerializeToHexStr())
	fmt.Println("分片公钥share_pk1: ", share_pks[0].SerializeToHexStr())

	fmt.Println("分片私钥share_sk1: ", share_sks[1].SerializeToHexStr())
	fmt.Println("分片公钥share_pk1: ", share_pks[1].SerializeToHexStr())

	fmt.Println("分片私钥share_sk1: ", share_sks[2].SerializeToHexStr())
	fmt.Println("分片公钥share_pk1: ", share_pks[2].SerializeToHexStr())

	//恢复私钥{1,2}
	recover_sk := bls.SecretKey{}
	new_id_list := make([]bls.ID, 2)
	for i := 0; i < 2; i++ {
		new_id_list[i] = *id_list[i]
	}
	err := recover_sk.Recover(share_sks[:2], new_id_list)
	if err != nil {
		// handle error
		fmt.Println("error", err)
		return
	}
	// fmt.Println("recover_sk: ", recover_sk)
	fmt.Println("recover_sk: ", recover_sk.SerializeToHexStr())

	//恢复私钥{2,3}
	for i := 0; i < 2; i++ {
		new_id_list[i] = *id_list[i+1]
	}
	err1 := recover_sk.Recover(share_sks[1:3], new_id_list)
	if err1 != nil {
		// handle error
		fmt.Println("error", err1)
		return
	}
	// fmt.Println("recover_sk: ", recover_sk)
	fmt.Println("recover_sk: ", recover_sk.SerializeToHexStr())

	//恢复私钥{1,3}
	// new_share_sks_list := make([]bls.SecretKey, 2)
	new_share_sks_list := []bls.SecretKey{share_sks[2], share_sks[0]}
	for i := 0; i < 2; i++ {
		new_id_list[i] = *id_list[(i+2)%3]
	}
	err2 := recover_sk.Recover(new_share_sks_list, new_id_list)
	if err2 != nil {
		// handle error
		fmt.Println("error", err2)
		return
	}
	// fmt.Println("recover_sk: ", recover_sk)
	fmt.Println("recover_sk: ", recover_sk.SerializeToHexStr())

	//公钥的recover {1,2}
	recover_pk := bls.PublicKey{}
	// new_id_list := make([]bls.ID, 2)
	for i := 0; i < 2; i++ {
		new_id_list[i] = *id_list[i]
	}
	err = recover_pk.Recover(share_pks[:2], new_id_list)
	if err != nil {
		// handle error
		fmt.Println("error", err)
		return
	}
	fmt.Println("recover_pk: ", recover_pk.SerializeToHexStr())

	//签名的recover {1,2}
	//签名消息
	msg := "hello, world!"
	sig_init := sk.Sign(msg)
	fmt.Println("初始的签名: ", sig_init.SerializeToHexStr())
	share_sigs := make([]bls.Sign, 2)
	for i := 0; i < 2; i++ {
		share_sigs[i] = *share_sks[i].Sign(msg)
	}
	recover_sig := bls.Sign{}
	err = recover_sig.Recover(share_sigs[:2], new_id_list)
	if err != nil {
		// handle error
		fmt.Println("error", err)
		return
	}
	fmt.Println("重构的签名: ", recover_sig.SerializeToHexStr())
}

func main() {
	fmt.Println("===================================get_keyshare() starts=====================================")
	get_keyshare()
	fmt.Println("===================================get_keyshare() ending=====================================\n")

	fmt.Println("===================================multi_sign() starts=======================================")
	multi_sign()
	fmt.Println("===================================multi_sign() ending=======================================")
}
