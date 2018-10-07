package main

import (
	"gopkg.in/mgo.v2/bson"
	//"golang.org/x/crypto/openpgp/packet"
	//"golang.org/x/tools/present"
)

// the configuration object
type Configuration struct{
	PortNumber string
	DbConnection string
	DbName string
	EthereumNode string
	EthereumAccount string
	EthereumPassword string
}

// The person Type (more like an object)
type PersonStruct struct {
	Identifier  string
	Name        string
	Phone       string
}

type StructKeys struct {
	PrivateKey          string `bson:"_PrivateKey"`
	PublicKey           string `bson:"_PublicKey"`
}
type StructKeysBinary struct{

	PrivateKey          []byte `bson:"_PrivateKey"`
	PublicKey           []byte `bson:"_PublicKey"`
}


type Logging struct{
	Event 				   string `bson:"_Event"`
	PublicKey  bson.Binary `bson:"_PublicKey"`
	BlockchainId           bson.Binary `bson:"_BlockChainId"`
}

type StructSystemInfo struct {
	ID                  bson.ObjectId `bson:"_Id,omitempty"`
	Version          string `bson:"_Version"`
	Client      string `bson:"_Client"`
}

type StructIdentity struct {
	ID                  bson.ObjectId `bson:"_Id,omitempty"`
	Identifier          string `bson:"_Identifier" json:"identifier"`
	ProtectionCode      string `bson:"_ProtectionCode" json:"protectionCode"`
	Keys                StructKeys `bson:"_Keys"`
}
type StructIdentityBinary struct {
	ID                  bson.ObjectId `bson:"_Id,omitempty"`
	Identifier          string `bson:"_Identifier"`
	ProtectionCode      string `bson:"_ProtectionCode"`
	Keys                StructKeysBinary `bson:"_Keys"`
}

type StructIdentityAttribute struct {
	ID                  bson.ObjectId `bson:"_Id,omitempty"`
	PubKey              string `bson:"_PubKey"`
	AttributeLabel      string `bson:"_AttributeLabel"`
	AttributeDataType   string `bson:"_AttributeDataType"`
	Data                string `bson:"_Data"`
}

type StructIdentityAttributeBinary struct {
PubKey              string `bson:"_PublicKey"`
AttributeLabel      string `bson:"_AttributeLabel"`
AttributeDataType   string `bson:"_AttributeDataType"`
Data                bson.Binary `bson:"_Data"`
}


type EthereumPostData struct{
	Jsonrpc string `bson:"jsonrpc" json"jsonrpc"`
	Method 	string `bson:"method" json"method"`
	Params []EthereumPostDataParams `bson:"params" json"params"`
	Id string `bson:"id" json"id"`

}
type EthereumPostDataParams struct{
	From string `bson:"from" json"from"`
	To string `bson:"to" json"to"`
	Datea string `bson:"data" json"data"`
}

type RPCResponse struct{
	Jsonrpc string `bson:"jsonrpc" json"jsonrpc"`
	Id string `bson:"id" json"id"`
	Result string `bson:"result" json"result"`

}

type PostResponse struct {
	Status        string `json:"status"`
	Message  	string `json:"message"`
	Code 		int   `json:"code"`
}


type IdentityResponse struct{
	Status      string `json:"status"`
	Pubkey  	string `json:"pubkey"`
}

type IdentityAttributesResponse struct{
	Status      string `json:"status"`
	Message  	string `json:"message"`
	Code 		int   `json:"code"`
	Attributes []StructIdentityAttribute `json:"attributes"`
}


type RegisterUser struct{

	PublicKey 	string `json:"publicKey"`
	Message  	string `json:"message"`
	OrgId  		string `json:"orgId"`
	UserId  	string `json:"userId"`
	Code 		string `json:"code"`
}

