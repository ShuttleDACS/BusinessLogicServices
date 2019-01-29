package main

// the configuration object
type Configuration struct {
	PortNumber string
}

type StructKeys struct {
	PrivateKey string `bson:"_PrivateKey"`
	PublicKey  string `bson:"_PublicKey"`
}

type StructSendTransaction struct {
	PublicKey string `json:"publicKey"`
	Message   string `json:"message"`
}

type StructCreateSignedTransaction struct {
	PrivateKey string `json:"privateKey"`
	Message    string `json:"message"`
}

type StructSetVal struct {
	ID string `json:"id"`
}
