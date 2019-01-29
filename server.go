package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/GoKillers/libsodium-go/cryptosign"
	"github.com/gorilla/mux"
)

// Globals
var AppConfig Configuration

/**
These are the flags that are set corresponding to a signature for the transaction
*/
var signatures = [3]bool{false, false, false}

/**
These are the keys that are required for signing a transaction
this data is hard coded intentionally and to be replaced for a new security policy
*/
var signingKeys = []string{}

/**
the current transaction, there can be only one
*/
var currentTransaction string = ""

/*--------------APIs-------------*/

func getReq(w http.ResponseWriter, r *http.Request) {

	/*
	   error := test(*mgoSession)


	   if error != nil {
	       fmt.Printf("insert fail %v\n", error)

	       response := PostResponse{"FAILURE", "DB Error", -1}
	       b, err2 := json.Marshal(response);
	       if err2 == nil {
	           w.Write(b)
	       }

	   } else {

	       fmt.Printf("insert ok ok %v\n", error)

	       response := PostResponse{"SUCCESS", "DB Lookup Success", 0}
	       b, err2 := json.Marshal(response);
	       if err2 == nil {
	           w.Write(b)
	       }
	   }

	*/

	b := []byte(`{"Status" : "SUCCESS", "signingKeys": "` + signingKeys[0] + "---" + signingKeys[1] + "---" + signingKeys[2] + `"}`)
	w.Write(b)

	/*
	   response := PostResponse{"SUCCESS", "Server is running",0}
	   b, err2 := json.Marshal(response);
	   if err2 == nil {
	       w.Write(b)
	   }
	*/
}

func generateSigningKeys(w http.ResponseWriter, r *http.Request) {

	signingKeys := _generateSigningKeys()

	b := []byte(`{"Status" : "SUCCESS", "secretKey": "` + signingKeys.PrivateKey + `", "publicKey" : ` + signingKeys.PublicKey + `"}`)
	w.Write(b)

}

func setValues(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			b := []byte(`{"Status" : "FAILURE", "message" : "panic error event "}`)
			w.Write(b)
			return
		}
	}()
	vals := StructSetVal{}

	err := json.NewDecoder(r.Body).Decode(&vals)
	if err != nil {
		b := []byte(`{"Status" : "FAILURE", "message" : "failed to parse json"}`)
		w.Write(b)
	} else {
		s := strings.Split(vals.ID, ",")
		signingKeys = s
		fmt.Println("keys recieved")
		b := []byte(`{"Status" : "Success", "message" : "keys successully stored "}`)
		w.Write(b)
		return
	}
}

func sendTransaction(w http.ResponseWriter, r *http.Request) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			b := []byte(`{"Status" : "FAILURE", "message" : "panic error event "}`)
			w.Write(b)
			return
		}
	}()
	sendTransaction := StructSendTransaction{}

	err := json.NewDecoder(r.Body).Decode(&sendTransaction)

	if err != nil {
		b := []byte(`{"Status" : "FAILURE", "message" : "failed to parse json"}`)
		w.Write(b)
	} else {

		// first lets ensure that public key sent is a key thats valid for this security policy
		var bValidKey bool = false

		// the index for this public key
		var keyIndex int = -1

		for x, key := range signingKeys {
			if key == sendTransaction.PublicKey {
				bValidKey = true
				keyIndex = x
			}

		}

		// the key provided is not part of the signing policy
		if !bValidKey {
			b := []byte(`{"Status" : "FAILURE", "message" : "unauthorized public key"}`)
			w.Write(b)
			return
		}

		// if we are here its a valid security policy pubkey

		// lets get the public key in binary
		fmt.Println("input=%v", sendTransaction)
		pkey, err := base64.StdEncoding.DecodeString(sendTransaction.PublicKey)
		if err != nil {
			b := []byte(`{"Status" : "FAILURE", "message" : "error retrieving public key"}`)
			w.Write(b)
		}

		/**
		  verify the signature of the message
		*/
		// decode the message from base 64
		encStr, err := base64.StdEncoding.DecodeString(sendTransaction.Message)
		str, res := cryptosign.CryptoSignOpen(encStr, pkey)

		debugLine := fmt.Sprintf("CryptoSignOpen res = %d, str = %s", res, str)
		fmt.Println(debugLine)

		if res != 0 {
			/**
			signature failure
			*/
			b := []byte(`{"Status" : "FAILURE", "message" : "signature failure"}`)
			w.Write(b)

			return

		} else {

			/**
			signature matches
			*/

			debugLine = fmt.Sprintf("current transaction = %s", currentTransaction)
			fmt.Println(debugLine)

			message := fmt.Sprintf("%s", str)
			// check for empty or new transacton
			if currentTransaction == "" || strings.Compare(currentTransaction, message) != 0 {

				debugLine = fmt.Sprintf("New Transaction, reseting flags")
				fmt.Println(debugLine)

				// clear the flags
				for x, _ := range signatures {
					signatures[x] = false

				}

				// reset the current transaction
				currentTransaction = message
				debugLine = fmt.Sprintf("New transaction set to: %s", message)
				fmt.Println(debugLine)

				// now set the flag for this key
				signatures[keyIndex] = true
				b := []byte(`{"Status" : "SUCCESS", "message" : "requires further approval"}`)
				w.Write(b)

				return

			} else {
				// existing transaction

				// now set the flag for this key
				signatures[keyIndex] = true
				var signedCount int = 0
				for _, signed := range signatures {
					if signed {
						signedCount++
					}
				}

				// ship it
				if signedCount >= 2 {
					b := []byte(`{"Status" : "SUCCESS", "message" : "transaction sent for signing"}`)
					w.Write(b)
					return

				} else {
					//waiting on signatures
					b := []byte(`{"Status" : "SUCCESS", "message" : "requires further approval"}`)
					w.Write(b)
					return
				}

			}
		}
	}
}

// MyServer .....
type MyServer struct {
	r *mux.Router
}

func (s *MyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		rw.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	}
	// Stop here if its Preflighted OPTIONS request
	if req.Method == "OPTIONS" {
		return
	}
	// Lets Gorilla work
	s.r.ServeHTTP(rw, req)
}

/*-------------------main----------------*/
func main() {
	fmt.Println("App starting")

	fmt.Println("Reading config file")

	raw, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Println("Error occured while reading config")
		return
	}
	json.Unmarshal(raw, &AppConfig)

	fmt.Printf("Running with configuration = \r\n%+v\n", AppConfig)

	// set up our apis
	router := mux.NewRouter()
	router.HandleFunc("/", getReq).Methods("GET")
	router.HandleFunc("/sendTransaction", sendTransaction).Methods("POST")

	// test apis
	router.HandleFunc("/testSigning", testSigning).Methods("POST")
	router.HandleFunc("/testCreateSignedMessage", testCreateSignedMessage).Methods("POST")
	router.HandleFunc("/setValues", setValues).Methods("POST")
	http.Handle("/", &MyServer{router})
	// start the server listening
	fmt.Println("Server starting to listen on port = %s", AppConfig.PortNumber)
	if err := http.ListenAndServe(AppConfig.PortNumber, nil); err != nil {
		panic(err)
	}

}
