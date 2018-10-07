package main

import (
	"fmt"
	"strconv"
	"reflect"
	"encoding/base64"
	"github.com/jamesruan/sodium"
)

func convertToHex(value string) string{

	var result string = ""
	a := []rune(value)
	for i, r := range a {
		fmt.Println(i)
		num,_ := strconv.ParseInt(string(r), 10, 64)
		fmt.Println("After :", reflect.TypeOf(num))
		convertInt := hexVal(num, true)
		result = result + convertInt
	}
	return result
}

func hexVal(i int64, prefix bool) string {
	i64 := int64(i)

	if prefix {
		return "0x" + strconv.FormatInt(i64, 16) // base 16 for hexadecimal
	} else {
		return strconv.FormatInt(i64, 16) // base 16 for hexadecimal
	}
}

func generateKeys()(keys StructKeys){

	var currKeys StructKeys
	kp := sodium.MakeBoxKP()
	pubKey := kp.SecretKey.PublicKey()
	secretKey := kp.SecretKey
	fmt.Println("Public Key: ", pubKey)
	fmt.Println("Secret Key: ",secretKey)

	fmt.Println("Public Bytes: ", pubKey.Bytes)
	pubKeyBytes := pubKey.Bytes
	strEncPublicKey := base64.StdEncoding.EncodeToString([]byte(pubKeyBytes))
	secretKeyBytes := secretKey.Bytes
	strEncSecretKey := base64.StdEncoding.EncodeToString([]byte(secretKeyBytes))

	currKeys.PrivateKey, currKeys.PublicKey = strEncSecretKey, strEncPublicKey
	return currKeys
}

func _generateSigningKeys()(keys StructKeys){

	var currKeys StructKeys
	kp := sodium.MakeSignKP()
	pubKey := kp.SecretKey.PublicKey()
	secretKey := kp.SecretKey
	fmt.Println("Public Key: ", pubKey)
	fmt.Println("Secret Key: ",secretKey)

	fmt.Println("Public Bytes: ", pubKey.Bytes)
	pubKeyBytes := pubKey.Bytes
	strEncPublicKey := base64.StdEncoding.EncodeToString([]byte(pubKeyBytes))
	secretKeyBytes := secretKey.Bytes
	strEncSecretKey := base64.StdEncoding.EncodeToString([]byte(secretKeyBytes))

	currKeys.PrivateKey, currKeys.PublicKey = strEncSecretKey, strEncPublicKey
	return currKeys

}