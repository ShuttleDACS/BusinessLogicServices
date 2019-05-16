package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/jamesruan/sodium"
	"gopkg.in/mgo.v2/bson"
)

const ServerIP = "192.168.0.102:2000"
const SecurityIP = "192.168.0.102:3000"

// var currKeys1 StructKeys
// var currKeys2 StructKeys
// var keys1 BoxKeysModel
// var keys2 BoxKeysModel

// PolicyData ..
type PolicyData struct {
	ID            bson.ObjectId `bson:"_id" json:"id"`
	Name          string        `bson:"name" json:"name"`
	WalletCreator string        `bson:"walletCreator" json:"walletCreator"`
	Signer        string        `bson:"signer" json:"signer"`
	SignerCount   string        `bson:"signerCount" json:"signerCount"`
}

// SuperAdminData ..
type SuperAdminData struct {
	ID                  bson.ObjectId `bson:"_id" json:"id"`
	Name                string        `bson:"name" json:"name"`
	Email               string        `bson:"email" json:"email"`
	Phone               string        `bson:"phone" json:"phone"`
	Admin               string        `bson:"admin" json:"admin"`
	PubKey              string        `bson:"pubKey" json:"pubkey"`
	SignKey             string        `bson:"signKey" json:"signKey"`
	ServerPrivKey       string        `bson:"servPrivKey" json:"servPrivKey"`
	ServerPubKey        string        `bson:"servPubKey" json:"servPubKey"`
	PendingTransactions string        `bson:"pendTrans" json:"pendTrans"`
}

func TestSetKeys(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("http://%s/dacs/getPolicies", ServerIP))
	var res []PolicyData
	if err != nil {
		t.Errorf("Connection Error  = %d", err)
	} else {
		data, _ := ioutil.ReadAll(resp.Body)
		errUn := json.Unmarshal(data, &res)
		if errUn != nil {
			t.Errorf("Unmarshalling Error  = %d", errUn)
		} else {
			if len(res) > 0 {
				jsonData := map[string]string{"id": bson.ObjectId(res[0].ID).Hex()}
				jsonValue, _ := json.Marshal(jsonData)
				response, err1 := http.Post(fmt.Sprintf("http://%s/setValues", SecurityIP), "application/json", bytes.NewBuffer(jsonValue))
				if err1 != nil {
					t.Errorf("Connection Error : %d", err1)
				} else {
					data1, _ := ioutil.ReadAll(response.Body)
					fmt.Println(string(data1))
					t.Log("keys successully stored through main server")
				}
			} else {
				t.Error("Sorry there is no seccurity policy added yet")
			}
		}
	}
}

func TestSigningTransaction4Wallet(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("http://%s/dacs/getPolicies", ServerIP))
	var res []PolicyData
	if err != nil {
		t.Errorf("Connection Error  = %d", err)
	} else {
		data, _ := ioutil.ReadAll(resp.Body)
		errUn := json.Unmarshal(data, &res)
		if errUn != nil {
			t.Errorf("Unmarshalling Error  = %d", errUn)
		} else {
			if len(res) > 0 {
				resp1, err2 := http.Get(fmt.Sprintf("http://%s/dacs/getSigners", ServerIP))
				var users []SuperAdminData
				var user SuperAdminData
				if err2 != nil {
					t.Errorf("Connection Error  = %d", err2)
				} else {
					data2, _ := ioutil.ReadAll(resp1.Body)
					errUnmar := json.Unmarshal(data2, &users)
					if errUnmar != nil {
						t.Errorf("Unmarshalling Error  = %d", errUnmar)
					} else {
						if len(users) > 0 {
							for _, key := range users {
								if key.SignKey == res[0].Signer {
									user = key
								}
							}
							//=====================================
							skp := sodium.MakeBoxKP()
							sPub, _ := base64.StdEncoding.DecodeString(user.ServerPubKey)
							var senderPubkeyByte []byte
							senderPubkeyByte = []byte(sPub)
							var sodPubObj sodium.BoxPublicKey
							sodPubObj.Bytes = senderPubkeyByte

							sPriv, _ := base64.StdEncoding.DecodeString(user.ServerPrivKey)
							var senderPrivkeyByte []byte
							senderPrivkeyByte = []byte(sPriv)
							var sodPrivObj sodium.BoxSecretKey
							sodPrivObj.Bytes = senderPrivkeyByte
							skp.PublicKey = sodPubObj
							skp.SecretKey = sodPrivObj

							n1 := sodium.BoxNonce{}
							sodium.Randomize(&n1)
							encodedNonce := base64.StdEncoding.EncodeToString([]byte(n1.Bytes))

							var nam = []string{"dacs2"}

							type JsonOb struct {
								Action string   `json:"action"`
								Params []string `json:"params"`
							}
							type SecretStruct struct {
								Secret string `json:"secret"`
							}
							type FilledIDStruct struct {
								FilledIdRequest SecretStruct `json:"filledIdRequest"`
							}
							var mesgObj JsonOb
							mesgObj.Action = "createWallet"
							mesgObj.Params = nam

							JsonedMsg, _ := json.Marshal(mesgObj)
							stringifyJson := string(JsonedMsg)
							var secretObj SecretStruct
							secretObj.Secret = stringifyJson

							var filledIDObj FilledIDStruct
							filledIDObj.FilledIdRequest = secretObj
							e, _ := json.Marshal(filledIDObj)
							fmt.Println(string(e))
							encText := sodium.Bytes(string(e))
							encMsg1 := encText.Box(n1, skp.PublicKey, skp.SecretKey)
							encodedmsg := base64.StdEncoding.EncodeToString([]byte(encMsg1))
							//============================================
							jsonData := map[string]string{"publicKey": user.PubKey, "message": encodedmsg, "nonce": encodedNonce, "sender": user.ServerPrivKey /*, "transName": recepient*/}
							jsonValue, _ := json.Marshal(jsonData)
							response, err1 := http.Post(fmt.Sprintf("http://%s/sendTransactionTest1", SecurityIP), "application/json", bytes.NewBuffer(jsonValue))
							if err1 != nil {
								t.Errorf("Connection Error : %d", err1)
							} else {
								data1, _ := ioutil.ReadAll(response.Body)
								fmt.Println(string(data1))
								t.Log("successfully signed")
							}
						} else {
							t.Error("Not Enough Users")
						}
					}
				}
			} else {
				t.Error("Sorry there is no seccurity policy added yet")
			}
		}
	}
}

func TestSigningTransaction4Account(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("http://%s/dacs/getPolicies", ServerIP))
	var res []PolicyData
	if err != nil {
		t.Errorf("Connection Error  = %d", err)
	} else {
		data, _ := ioutil.ReadAll(resp.Body)
		errUn := json.Unmarshal(data, &res)
		if errUn != nil {
			t.Errorf("Unmarshalling Error  = %d", errUn)
		} else {
			if len(res) > 0 {
				resp1, err2 := http.Get(fmt.Sprintf("http://%s/dacs/getSigners", ServerIP))
				var users []SuperAdminData
				var user SuperAdminData
				if err2 != nil {
					t.Errorf("Connection Error  = %d", err2)
				} else {
					data2, _ := ioutil.ReadAll(resp1.Body)
					errUnmar := json.Unmarshal(data2, &users)
					if errUnmar != nil {
						t.Errorf("Unmarshalling Error  = %d", errUnmar)
					} else {
						if len(users) > 0 {
							for _, key := range users {
								if key.SignKey == res[0].Signer {
									user = key
								}
							}
							//=====================================
							skp := sodium.MakeBoxKP()
							sPub, _ := base64.StdEncoding.DecodeString(user.ServerPubKey)
							var senderPubkeyByte []byte
							senderPubkeyByte = []byte(sPub)
							var sodPubObj sodium.BoxPublicKey
							sodPubObj.Bytes = senderPubkeyByte

							sPriv, _ := base64.StdEncoding.DecodeString(user.ServerPrivKey)
							var senderPrivkeyByte []byte
							senderPrivkeyByte = []byte(sPriv)
							var sodPrivObj sodium.BoxSecretKey
							sodPrivObj.Bytes = senderPrivkeyByte
							skp.PublicKey = sodPubObj
							skp.SecretKey = sodPrivObj

							n1 := sodium.BoxNonce{}
							sodium.Randomize(&n1)
							encodedNonce := base64.StdEncoding.EncodeToString([]byte(n1.Bytes))

							var nam = []string{"dacs2"}

							type JsonOb struct {
								Action string   `json:"action"`
								Params []string `json:"params"`
							}
							type SecretStruct struct {
								Secret string `json:"secret"`
							}
							type FilledIDStruct struct {
								FilledIdRequest SecretStruct `json:"filledIdRequest"`
							}
							var mesgObj JsonOb
							mesgObj.Action = "getNewAddress"
							mesgObj.Params = nam

							JsonedMsg, _ := json.Marshal(mesgObj)
							stringifyJson := string(JsonedMsg)
							var secretObj SecretStruct
							secretObj.Secret = stringifyJson

							var filledIDObj FilledIDStruct
							filledIDObj.FilledIdRequest = secretObj
							e, _ := json.Marshal(filledIDObj)
							fmt.Println(string(e))
							encText := sodium.Bytes(string(e))
							encMsg1 := encText.Box(n1, skp.PublicKey, skp.SecretKey)
							encodedmsg := base64.StdEncoding.EncodeToString([]byte(encMsg1))
							//============================================
							jsonData := map[string]string{"publicKey": user.PubKey, "message": encodedmsg, "nonce": encodedNonce, "sender": user.ServerPrivKey /*, "transName": recepient*/}
							jsonValue, _ := json.Marshal(jsonData)
							response, err1 := http.Post(fmt.Sprintf("http://%s/sendTransactionTest1", SecurityIP), "application/json", bytes.NewBuffer(jsonValue))
							if err1 != nil {
								t.Errorf("Connection Error : %d", err1)
							} else {
								data1, _ := ioutil.ReadAll(response.Body)
								fmt.Println(string(data1))
								t.Log("successfully signed")
							}
						} else {
							t.Error("Not Enough Users")
						}
					}
				}
			} else {
				t.Error("Sorry there is no seccurity policy added yet")
			}
		}
	}
}

func TestGetWalletBallance(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("http://%s/dacs/getPolicies", ServerIP))
	var res []PolicyData
	if err != nil {
		t.Errorf("Connection Error  = %d", err)
	} else {
		data, _ := ioutil.ReadAll(resp.Body)
		errUn := json.Unmarshal(data, &res)
		if errUn != nil {
			t.Errorf("Unmarshalling Error  = %d", errUn)
		} else {
			if len(res) > 0 {
				resp1, err2 := http.Get(fmt.Sprintf("http://%s/dacs/getSigners", ServerIP))
				var users []SuperAdminData
				var user SuperAdminData
				if err2 != nil {
					t.Errorf("Connection Error  = %d", err2)
				} else {
					data2, _ := ioutil.ReadAll(resp1.Body)
					errUnmar := json.Unmarshal(data2, &users)
					if errUnmar != nil {
						t.Errorf("Unmarshalling Error  = %d", errUnmar)
					} else {
						if len(users) > 0 {
							for _, key := range users {
								if key.SignKey == res[0].Signer {
									user = key
								}
							}
							//=====================================
							skp := sodium.MakeBoxKP()
							sPub, _ := base64.StdEncoding.DecodeString(user.ServerPubKey)
							var senderPubkeyByte []byte
							senderPubkeyByte = []byte(sPub)
							var sodPubObj sodium.BoxPublicKey
							sodPubObj.Bytes = senderPubkeyByte

							sPriv, _ := base64.StdEncoding.DecodeString(user.ServerPrivKey)
							var senderPrivkeyByte []byte
							senderPrivkeyByte = []byte(sPriv)
							var sodPrivObj sodium.BoxSecretKey
							sodPrivObj.Bytes = senderPrivkeyByte
							skp.PublicKey = sodPubObj
							skp.SecretKey = sodPrivObj

							n1 := sodium.BoxNonce{}
							sodium.Randomize(&n1)
							encodedNonce := base64.StdEncoding.EncodeToString([]byte(n1.Bytes))

							action := []byte(`{"filledIDRequest" : { "secret"  : "getWalletBalance" } }`)
							encText := sodium.Bytes(string(action))
							encMsg1 := encText.Box(n1, skp.PublicKey, skp.SecretKey)
							encodedmsg := base64.StdEncoding.EncodeToString([]byte(encMsg1))
							//============================================
							jsonData := map[string]string{"publicKey": user.PubKey, "message": encodedmsg, "nonce": encodedNonce, "sender": user.ServerPrivKey}
							jsonValue, _ := json.Marshal(jsonData)
							response, err1 := http.Post(fmt.Sprintf("http://%s/sendTransactionTest1", SecurityIP), "application/json", bytes.NewBuffer(jsonValue))
							if err1 != nil {
								t.Errorf("Connection Error : %d", err1)
							} else {
								data1, _ := ioutil.ReadAll(response.Body)
								fmt.Println(string(data1))
								t.Log("successfully signed")
							}
						} else {
							t.Error("Not Enough Users")
						}
					}
				}
			} else {
				t.Error("Sorry there is no seccurity policy added yet")
			}
		}
	}
}

func TestSigningTransaction4SendTo(t *testing.T) {
	resp, err := http.Get(fmt.Sprintf("http://%s/dacs/getPolicies", ServerIP))
	var res []PolicyData
	if err != nil {
		t.Errorf("Connection Error  = %d", err)
	} else {
		data, _ := ioutil.ReadAll(resp.Body)
		errUn := json.Unmarshal(data, &res)
		if errUn != nil {
			t.Errorf("Unmarshalling Error  = %d", errUn)
		} else {
			if len(res) > 0 {
				resp1, err2 := http.Get(fmt.Sprintf("http://%s/dacs/getSigners", ServerIP))
				var users []SuperAdminData
				var user SuperAdminData
				if err2 != nil {
					t.Errorf("Connection Error  = %d", err2)
				} else {
					data2, _ := ioutil.ReadAll(resp1.Body)
					errUnmar := json.Unmarshal(data2, &users)
					if errUnmar != nil {
						t.Errorf("Unmarshalling Error  = %d", errUnmar)
					} else {
						if len(users) > 0 {
							for _, key := range users {
								if key.SignKey == res[0].Signer {
									user = key
								}
							}
							//=====================================
							skp := sodium.MakeBoxKP()
							sPub, _ := base64.StdEncoding.DecodeString(user.ServerPubKey)
							var senderPubkeyByte []byte
							senderPubkeyByte = []byte(sPub)
							var sodPubObj sodium.BoxPublicKey
							sodPubObj.Bytes = senderPubkeyByte

							sPriv, _ := base64.StdEncoding.DecodeString(user.ServerPrivKey)
							var senderPrivkeyByte []byte
							senderPrivkeyByte = []byte(sPriv)
							var sodPrivObj sodium.BoxSecretKey
							sodPrivObj.Bytes = senderPrivkeyByte
							skp.PublicKey = sodPubObj
							skp.SecretKey = sodPrivObj

							n1 := sodium.BoxNonce{}
							sodium.Randomize(&n1)
							encodedNonce := base64.StdEncoding.EncodeToString([]byte(n1.Bytes))

							var nam = []string{"dacs2", "0.0001", "asdh62c87asvd87asdvada"}

							type JsonOb struct {
								Action string   `json:"action"`
								Params []string `json:"params"`
							}
							type SecretStruct struct {
								Secret string `json:"secret"`
							}
							type FilledIDStruct struct {
								FilledIdRequest SecretStruct `json:"filledIdRequest"`
							}
							var mesgObj JsonOb
							mesgObj.Action = "sendBitcoin"
							mesgObj.Params = nam

							JsonedMsg, _ := json.Marshal(mesgObj)
							stringifyJson := string(JsonedMsg)
							var secretObj SecretStruct
							secretObj.Secret = stringifyJson

							var filledIDObj FilledIDStruct
							filledIDObj.FilledIdRequest = secretObj
							e, _ := json.Marshal(filledIDObj)
							fmt.Println(string(e))
							encText := sodium.Bytes(string(e))
							encMsg1 := encText.Box(n1, skp.PublicKey, skp.SecretKey)
							encodedmsg := base64.StdEncoding.EncodeToString([]byte(encMsg1))
							//============================================
							jsonData := map[string]string{"publicKey": user.PubKey, "message": encodedmsg, "nonce": encodedNonce, "sender": user.ServerPrivKey /*, "transName": recepient*/}
							jsonValue, _ := json.Marshal(jsonData)
							response, err1 := http.Post(fmt.Sprintf("http://%s/sendTransactionTest1", SecurityIP), "application/json", bytes.NewBuffer(jsonValue))
							if err1 != nil {
								t.Errorf("Connection Error : %d", err1)
							} else {
								data1, _ := ioutil.ReadAll(response.Body)
								fmt.Println(string(data1))
								t.Log("successfully signed")
							}
						} else {
							t.Error("Not Enough Users")
						}
					}
				}
			} else {
				t.Error("Sorry there is no seccurity policy added yet")
			}
		}
	}
}
