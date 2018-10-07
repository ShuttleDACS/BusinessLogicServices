package main

import (
	"encoding/hex"
	"fmt"
	"encoding/json"
	"net/http"
	"bytes"
	"io/ioutil"
	"gopkg.in/mgo.v2/bson"
)

func unlockAccount() {
	//curl -X POST --data '{"jsonrpc":"2.0","method":"personal_unlockAccount","params":["0x7642b...", "password", 3600],"id":67}' http://localhost:8545
	//{"jsonrpc":"2.0","id":67,"result":true}


	s := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"personal_unlockAccount\",\"params\":[\"%s\", \"%s\", 3600],\"id\":67}", AppConfig.EthereumAccount, AppConfig.EthereumPassword)
	in := []byte(s)
	var raw map[string]interface{}
	json.Unmarshal(in, &raw)
	// add count to json
	//raw["count"] = 1
	out, _ := json.Marshal(raw)
	println(string(out))

	request_eth, _ := http.NewRequest("POST", AppConfig.EthereumNode, bytes.NewBuffer(out))
	request_eth.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response_eth, err := client.Do(request_eth)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response_eth.Body)
		fmt.Println(string(data))

		rpcResponse := new(RPCResponse)
		json.Unmarshal(data, &rpcResponse)

	}
}

func writeToBlockChain(Event string, PublicKey string, jsonObject string) {

	unlockAccount()


	encodedStr := hex.EncodeToString([]byte(jsonObject))
	fmt.Println("clear data to be stored in blockchain", jsonObject)
	fmt.Println("hex data to be stored in blockchain", "0x"+encodedStr)

	params := EthereumPostDataParams{AppConfig.EthereumAccount, AppConfig.EthereumAccount, encodedStr}
	postData := EthereumPostData{"2.0", "eth_sendTransaction", []EthereumPostDataParams{params}, "99"}

	fmt.Println("Ethereum Post Data ", postData)

	jsonValue, _ := json.Marshal(postData)
	request_eth, _ := http.NewRequest("POST", AppConfig.EthereumNode, bytes.NewBuffer(jsonValue))
	request_eth.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response_eth, err := client.Do(request_eth)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response_eth.Body)
		fmt.Println(string(data))

		rpcResponse := new(RPCResponse)
		json.Unmarshal(data, &rpcResponse)

		loggingData := Logging{
			Event: 		Event,
			PublicKey:     bson.Binary{0, []byte(PublicKey)},

			BlockchainId:  bson.Binary{0, []byte(rpcResponse.Result)},
		}



		err = writeToBlockChainCollection(loggingData, *mgoSession)

		if err != nil {

			fmt.Printf("Logging failed  with error %s\n", err.Error())
		}

		fmt.Println("Successfully logged ")
		return;
	}

}
