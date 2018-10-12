package main

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"fmt"
	//"time"
)


const strCollectionIdentityAttribute    = "IdentityAttributes"
const strCollectionBlockChain           = "BlockChain"
const strCollectionIdentities           = "Identities"
const strCollectionSystemInfo 			= "SystemInfo"




func test(session mgo.Session) ( error) {

	s := session.Clone()
	defer s.Close()

	//error check on every access
	s.SetSafe(&mgo.Safe{})

	c := s.DB(AppConfig.DbName).C(strCollectionIdentityAttribute)



	err := c.Insert(bson.M{"_PUublicKey" : "1yv0SwIIoDKdtnMNOoXgjXCPLgjM/iC5ciknIPOhpnc=", "test" : "yada"})
	if err != nil {
		return err
	}else
	{
		return  nil
	}

}

func writeToIdenityCollection(binary StructIdentityBinary, session mgo.Session) error {

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C(strCollectionIdentities)

	err := c.Insert(&binary)
	if err != nil {
		return err
	} else {
		return nil
	}

}

func writeToBlockChainCollection(logging Logging, session mgo.Session) error {

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C(strCollectionBlockChain)

	err := c.Insert(&logging)

	if err != nil {
		return err
	} else {
		return nil
	}

}


func getSystemInfoCollection(session mgo.Session) ([]StructSystemInfo , error) {

	s := session.Clone()
	defer s.Close()

	//error check on every access
	s.SetSafe(&mgo.Safe{})

	c := s.DB(AppConfig.DbName).C(strCollectionSystemInfo)

	var results []StructSystemInfo
	err := c.Find(bson.M{}).All(&results)

	return results, err

}


func getIdentitity(identifier string, protectionCode string, session mgo.Session) ([]StructIdentity , error) {

	s := session.Clone()
	defer s.Close()

	//error check on every access
	s.SetSafe(&mgo.Safe{})

	c := s.DB(AppConfig.DbName).C(strCollectionIdentities)


	var identities []StructIdentity
	err := c.Find(bson.M{"_Identifier":identifier, "_ProtectionCode":protectionCode}).Sort("_Identifier").All(&identities)
	if err != nil {
		return nil, err
	}else
	{
		return identities, nil
	}

}


func getIdentityAttrbutes(publicKey string, label string, dataType string,  session mgo.Session) ([]StructIdentityAttribute, error) {

	s := session.Clone()
	defer s.Close()

	//error check on every access
	s.SetSafe(&mgo.Safe{})

	c := s.DB(AppConfig.DbName).C(strCollectionIdentityAttribute)

	var identityAttributes []StructIdentityAttribute


	if label != "" {
		// lookup attributes by label
		err := c.Find(bson.M{"_PublicKey": publicKey, "_AttributeLabel":label}).Sort("_AttributeLabel").All(&identityAttributes)
		if err != nil {
			return nil, err
		}else
		{

			fmt.Println("attributes=>", identityAttributes)
			return identityAttributes, nil
		}

	} else{
		// lookup attributes by dataType

		fmt.Println("attribuet data type = %s", dataType)
		err := c.Find(bson.M{"_PublicKey": publicKey, "_AttributeDataType":dataType}).Sort("_AttributeDataType").All(&identityAttributes)
		if err != nil {
			return nil, err
		}else
		{
			return identityAttributes, nil
		}

	}
}


func writeToIdentityAttrbutesCollection(identityAttribute StructIdentityAttribute, session mgo.Session) error {

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C(strCollectionIdentityAttribute)

	identityAttributeBinary := StructIdentityAttributeBinary{(identityAttribute.PubKey),
	identityAttribute.AttributeLabel, identityAttribute.AttributeDataType, bson.Binary{0, []byte(identityAttribute.Data)}}

	err := c.Insert(&identityAttributeBinary)
	if err != nil {
		return err
	} else {
		return nil
	}

}

func updateRegisterUser(registerUser StructRegisterUser, session mgo.Session) error {

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C("users")


	fmt.Printf("registerUser = %v\n", registerUser)
	// Update
	pubkey := registerUser.PublicKey
	selector := bson.M{"organization_id": registerUser.OrgId, "user_id" : registerUser.UserId, "registration_code" : registerUser.Code}
	updator := bson.M{"$set": bson.M{"publicKey": pubkey}}
	if err := c.Update(selector, updator); err != nil {
		return err
	}else{
		return nil
	}
}

func getTransaction(organization_id string, session mgo.Session) (StructTransaction, error) {

	s := session.Clone()
	defer s.Close()

	//error check on every access
	s.SetSafe(&mgo.Safe{})

	c := s.DB(AppConfig.DbName).C("transactions")


	var transaction StructTransaction
	err := c.Find(bson.M{"organization_id":organization_id}).One(&transaction)
	if err != nil {
		return transaction, err
	}else
	{
		return transaction, nil
	}

}
func resetTransaction(transaction StructTransaction, session mgo.Session) error {

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C("transactions")


	fmt.Printf("transaction = %v\n", transaction)
	// Update
	organization_id := transaction.Organization_id
	selector := bson.M{"organization_id": organization_id}

	updator := bson.M{"$set": bson.M{"transaction": transaction.Transaction, "signers" :[]string{transaction.PublicKey}, "status" : "QUEUED"}}

	err := c.Update(selector, updator)
	if(err != nil) {
		return err
	} else{
		return nil
	}


}

func updateTransactionSigners(organization_id string, signers []string,  session mgo.Session) error {

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C("transactions")


	//fmt.Printf("transaction = %v\n", transaction)
	// Update
	//organization_id := transaction.Organization_id
	selector := bson.M{"organization_id": organization_id}

	updator := bson.M{"$set": bson.M{ "signers" : signers, "status" : "QUEUED"}}

	err := c.Update(selector, updator)
	if(err != nil) {
		return err
	} else{
		return nil
	}


}
func getRequiredSignatures(organization_id string, session mgo.Session) ([]string, error){

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C("signers")


	var signers StructSigners
	err := c.Find(bson.M{"organization_id":organization_id}).One(&signers)
	if err != nil {
		return signers.Signers, err
	}else
	{
		return signers.Signers, nil
	}
}

func updateTransactionSignatures(organization_id string, required_signatures [] string, signature string, session mgo.Session)(string, error){

	s := session.Clone()
	c := s.DB(AppConfig.DbName).C("transactions")


	var transaction StructTransaction
	err := c.Find(bson.M{"organization_id":organization_id}).One(&transaction)
	if err != nil {
		return "", err
	}else
	{

		var found bool = false;
		for index, element := range transaction.Signers{

			fmt.Println("index  %d", index)
			fmt.Println("signature %s", element)

			if(element == signature){
				found = true
				break;
			}

		}

		if(found != true){

			selector := bson.M{"organization_id": organization_id}


			transaction.Signers = append(transaction.Signers, signature)
			updator := bson.M{"$set": bson.M{ "signers" : transaction.Signers, "status" : "QUEUED"}}

			err := c.Update(selector, updator)
			if(err != nil) {
				return "", err
			}

			var status string;
			if(len(required_signatures) == len(transaction.Signers)) {
				status = "PROCESS"
			}else{
				status = "QUEUED"
			}


			updator = bson.M{"$set": bson.M{ "status" : status}}

			err = c.Update(selector, updator)
			if(err != nil) {
				return "", err
			} else{
				return status, nil
			}

		}
		return "", nil
	}
}
