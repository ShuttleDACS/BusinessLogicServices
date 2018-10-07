package main

import (
	"github.com/GoKillers/libsodium-go/cryptosign"
	"fmt"
	"net/http"
	"encoding/base64"

)

func testCreateSignedMessage(w http.ResponseWriter, r *http.Request){

	skey, err1 := base64.StdEncoding.DecodeString("PaJFkd/75KbKN29/R1aHUUIurZdFKco65ewra8wjRJMlkLXXnlMTPKQBwx6KSi+GnWB/T0Iqisor6ByqaJkcHA==")


	message := []byte(`{"orgId":"shuttle_fund", "userId" : "yada", "code" : "123456789"}`)

	if(err1 != nil){

		b := []byte(`{"Status" : "FAILURE", "message: "failure to decode secret key"}`)
		w.Write(b)

		return;
	}

	signedStr, res := cryptosign.CryptoSign(message, skey)

	encStr := base64.StdEncoding.EncodeToString([]byte(signedStr))

	fmt.Println("signed message", string(signedStr[:]))
	fmt.Println("base64", encStr)

	if(res != 0) {
		b := []byte(`{"Status" : "FAILURE", "message: "failed to sign message}`)
		w.Write(b)
		return;

	}else {
		b := []byte(`{"Status" : "SUCCESS", "message: "` + string(encStr[:])+ `"}`)
		w.Write(b)
	}

}

func testSigning(w http.ResponseWriter, r *http.Request){

		skey, err1 := base64.StdEncoding.DecodeString("PaJFkd/75KbKN29/R1aHUUIurZdFKco65ewra8wjRJMlkLXXnlMTPKQBwx6KSi+GnWB/T0Iqisor6ByqaJkcHA==")


		/**
		good pubkey = ZC1155TEzykAcMeikovhp1gf09CKorKK+gcqmiZHBw=
		bad pubkey =  YADA55TEzykAcMeikovhp1gf09CKorKK+gcqmiZHBw=
		 */
		pkey, err2 := base64.StdEncoding.DecodeString("YADA155TEzykAcMeikovhp1gf09CKorKK+gcqmiZHBw=")
		if(err1 != nil){

			b := []byte(`{"Status" : "FAILURE", "message: "failure to decode secret key"}`)
			w.Write(b)

			return;
		}
		if(err2 != nil){
			b := []byte(`{"Status" : "FAILURE", "message: "failure to decode public key"}`)
			w.Write(b)
			return;

		}
		signedStr, res := cryptosign.CryptoSign([]byte("test message"), skey)

		fmt.Println("signed message", string(signedStr[:]))
		fmt.Println("size", res)

		if(res != 0) {
			b := []byte(`{"Status" : "FAILURE", "message: "failed to sign message}`)
			w.Write(b)
			return;
		}


		str, res := cryptosign.CryptoSignOpen(signedStr, pkey)

		fmt.Println("message", string(str[:]))
		fmt.Println("size", res)

		if(res != 0) {
			b := []byte(`{"Status" : "FAILURE", "message: "signature failed for pubkey}`)
			w.Write(b)
			return;

		}else {
			b := []byte(`{"Status" : "SUCCESS", "message: "` + string(str[:])+ `"}`)
			w.Write(b)
		}

}
