package sign_agg

import (
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"
)

func agg_sign() {
	// 初始化BLS签名库
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		fmt.Println("Error initializing BLS library:", err)
		return
	}

	// 生成私钥和公钥
	sk1 := bls.SecretKey{}
	sk1.SetByCSPRNG()
	pk1 := sk1.GetPublicKey()

	sk2 := bls.SecretKey{}
	sk2.SetByCSPRNG()
	pk2 := sk2.GetPublicKey()

	fmt.Println("私钥1", sk1)
	fmt.Println("公钥1", pk1)
	fmt.Println("私钥2", sk2)
	fmt.Println("公钥2", pk2)

	// 需要聚合的签名
	sig1 := sk1.Sign("hello")
	sig2 := sk2.Sign("hello") //这里因为没有对消息做hash,所以在最后聚合数据处消息数据的大小不一致，所以测试中还是采用一样的消息

	// 聚合签名
	aggSig := bls.Sign{}
	aggSig.Aggregate([]bls.Sign{*sig1, *sig2})
	// aggSig.Add(sig1)
	// aggSig.Add(sig2)

	// 聚合公钥
	aggPk := bls.PublicKey{}
	aggPk.Add(pk1)
	aggPk.Add(pk2)

	//验证聚合签名
	fmt.Println("aggSig verify result:", aggSig.Verify(&aggPk, "hello"))

}
