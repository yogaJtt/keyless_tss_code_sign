package sign_single

import (
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"
)

func single_sign() {
	// 初始化BLS签名库
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		fmt.Println("Error initializing BLS library:", err)
		return
	}

	// 生成公私钥对
	sk := bls.SecretKey{}
	sk.SetByCSPRNG()
	pk := sk.GetPublicKey()

	// 签名消息
	msg := []byte("hello, world!")
	sig := sk.SignByte(msg)

	// 验证签名
	valid := sig.VerifyByte(pk, msg)
	fmt.Println("Signature valid?", valid)
}
