package main

import (
	"github.com/GoKillers/libsodium-go/cryptosign"
	"fmt"
	"net/http"
	"encoding/base64"

	"encoding/json"
)

func testCreateSignedMessage(w http.ResponseWriter, r *http.Request){


	structCreateSignedTransaction := StructCreateSignedTransaction{}

	err := json.NewDecoder(r.Body).Decode(&structCreateSignedTransaction)

	if (err != nil) {
		b := []byte(`{"Status" : "FAILURE", "message" : "failed to parse json"}`)
		w.Write(b)
	}


	fmt.Println("%v", structCreateSignedTransaction)

	//skey, err1 := base64.StdEncoding.DecodeString("F1jd4BQz7T1ul/GAXHDnr7m/LJp0G6ZcVgJHfFq3LpfoAX5dgrR5Fct2QrJGHH2y5WELFc904KEr8h8Gk2PI7w==")
	skey, err1 := base64.StdEncoding.DecodeString(structCreateSignedTransaction.PrivateKey)

	if(err1 != nil){

		b := []byte(`{"Status" : "FAILURE", "message: "failure to decode secret key"}`)
		w.Write(b)

		return;
	}


	message, err1  := base64.StdEncoding.DecodeString(structCreateSignedTransaction.Message)
	//message := []byte(structCreateSignedTransaction.Message)

	if(err1 != nil){

		b := []byte(`{"Status" : "FAILURE", "message: "failure to decode message}`)
		w.Write(b)

		return;
	}

	fmt.Println("skey", skey)
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
