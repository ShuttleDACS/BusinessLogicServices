// Entrypoint for API
package main
import (
    "encoding/json"
    "log"
    "net/http"
    "github.com/gorilla/mux"
	mgo "gopkg.in/mgo.v2"
    "gopkg.in/mgo.v2/bson"
    "io/ioutil"
    "fmt"
    //"crypto/tls"
    //"net"
    //"crypto"
    "github.com/GoKillers/libsodium-go/cryptosign"
    //"strconv"
    "encoding/base64"
    //"encoding/hex"
    //"debug/elf"

)



// Globals
var AppConfig Configuration
var people []PersonStruct
var mgoSession *mgo.Session



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


    response := PostResponse{"SUCCESS", "Server is running", 0}
    b, err2 := json.Marshal(response);
    if err2 == nil {
        w.Write(b)
    }
}


func generateSigningKeys(w http.ResponseWriter, r *http.Request) {

    signingKeys := _generateSigningKeys()


    b := []byte(`{"Status" : "SUCCESS", "secretKey": "` + signingKeys.PrivateKey + `", "publicKey" : ` + signingKeys.PublicKey + `"}`)
    w.Write(b)
}




func register(w http.ResponseWriter, r *http.Request){

    registerUser := StructRegisterUser{}

    err := json.NewDecoder(r.Body).Decode(&registerUser)

    if (err != nil) {
        b := []byte(`{"Status" : "FAILURE", "message" : "failed to parse json"}`)
        w.Write(b)
    } else
    {

        pkey, err := base64.StdEncoding.DecodeString(registerUser.PublicKey)
        if(err != nil){

        }


        /**
        verify the signature of the message
         */
        encStr, err := base64.StdEncoding.DecodeString(registerUser.Message)
        str, res := cryptosign.CryptoSignOpen(encStr, pkey)


        /**
        signature failure
         */
        if(res != 0){
            b := []byte(`{"Status" : "Failure", "message" : "signature failure"}`)
            w.Write(b)

        }else{

            var registerUser1 StructRegisterUser

            fmt.Printf("json string = %s", string(str[:]))
            json.Unmarshal(str[:], &registerUser1)
            registerUser1.PublicKey = registerUser.PublicKey

            fmt.Printf("json object = %v", registerUser1)
            fmt.Printf("orgid=%s userid=%s code=%s", registerUser1.OrgId, registerUser1.UserId, registerUser1.Code)

            err = updateRegisterUser(registerUser1, *mgoSession)
            if(err != nil){
                b := []byte(`{"Status" : "Failure", "message": "failed to update usersa"}`)
                w.Write(b)
            }else{
                b := []byte(`{"Status" : "SUCCESS", "message": "` + string(str[:])    + `"}`)
                w.Write(b)
            }


        }

    }
}


func sendTransaction(w http.ResponseWriter, r *http.Request){

    sendTransaction := StructSendTransaction{}

    err := json.NewDecoder(r.Body).Decode(&sendTransaction)

    if (err != nil) {
        b := []byte(`{"Status" : "FAILURE", "message" : "failed to parse json"}`)
        w.Write(b)
    } else
    {


        fmt.Println("input=%v", sendTransaction)
        pkey, err := base64.StdEncoding.DecodeString(sendTransaction.PublicKey)
        if(err != nil){

        }


        /**
        verify the signature of the message
         */
        encStr, err := base64.StdEncoding.DecodeString(sendTransaction.Message)
        str, res := cryptosign.CryptoSignOpen(encStr, pkey)


        var tx StructTransaction1
        json.Unmarshal([]byte(str), &tx)

        fmt.Println("tx1=%v", tx)
        /**
        signature failure
         */
        if(res != 0){
            b := []byte(`{"Status" : "Failure", "message" : "signature failure"}`)
            w.Write(b)

        }else{



            tx2, err := getTransaction(tx.Organization_id, *mgoSession)
            if(err != nil) {
                b := []byte(`{"Status" : "FAILURE", "message": "organization not found"}`)
                w.Write(b)

            }else{

                fmt.Println("tx2=%v", tx2)


                /**
                if the transaction is not equal to the incoming transaction, overwrite and add pubkey to signatures
                 */

                 if(tx2.Transaction != tx.SendTransaction){
                     // update the transacton and clear all pubkeys and add this one

                     tx2.PublicKey = sendTransaction.PublicKey
                     tx2.Transaction = tx.SendTransaction
                     err := resetTransaction(tx2, *mgoSession)
                     if(err != nil){
                         b := []byte(`{"Status" : "ERROR", "message": "update failed"}`)
                         w.Write(b)
                     }
                 }else{
                     /**
				  if the transaction is the current transaction then verify all required signatures are present
				  if not just add this transaction
				   */


				   fmt.Println("Updating existing transaction")
				   // get the required signatures
				   signers, err := getRequiredSignatures(tx.Organization_id, *mgoSession)
				   if(err != nil){
				       log.Fatal(err)
                       b := []byte(`{"Status" : "ERROR", "message": "failed to get signers"}`)
                       w.Write(b)
                   }else{

                       // check to see


                       var required  bool
                       required = false
                       for index, element := range signers{

                           fmt.Println("index  %d", index)
                           fmt.Println("signature %s", element)

                           if(element == sendTransaction.PublicKey){
                               fmt.Println("this signature is required")
                               required = true
                               break;
                           }

                       }

                       // get the signatures on the

                       if(required){
                           // determine if this signature has been provided
                           status, err1 := updateTransactionSignatures(tx.Organization_id, signers, sendTransaction.PublicKey, *mgoSession)
                           if(err1 != nil){

                           } else{
                               b := []byte(`{"Status" : "SUCCESS", "message": "transaction updated to ` + status + `"}`)
                               w.Write(b)
                           }

                       }else{

                           b := []byte(`{"Status" : "FAILURE", "message": "invalid public key"}`)
                           w.Write(b)
                       }


                   }


                 }



                b := []byte(`{"Status" : "SUCCESS", "message": "` + tx2.Transaction + `"}`)
                w.Write(b)
            }


            /*
            var registerUser1 StructRegisterUser

            fmt.Printf("json string = %s", string(str[:]))
            json.Unmarshal(str[:], &registerUser1)
            registerUser1.PublicKey = registerUser.PublicKey

            fmt.Printf("json object = %v", registerUser1)
            fmt.Printf("orgid=%s userid=%s code=%s", registerUser1.OrgId, registerUser1.UserId, registerUser1.Code)

            err = updateRegisterUser(registerUser1, *mgoSession)
            if(err != nil){
                b := []byte(`{"Status" : "Failure", "message": "failed to update usersa"}`)
                w.Write(b)
            }else{
                b := []byte(`{"Status" : "SUCCESS", "message": "` + string(str[:])    + `"}`)
                w.Write(b)
            }
            */


        }

    }
}

func getIdentityAttributesByDataType(w http.ResponseWriter, r *http.Request) {
    identityAttribute := StructIdentityAttribute{}

    err := json.NewDecoder(r.Body).Decode(&identityAttribute)
    if (err != nil) {
        w.Write([]byte("JSON Parsing Error"))
    }

    fmt.Println("input object: ", identityAttribute)

    identityAttributes, err := getIdentityAttrbutes(identityAttribute.PubKey, "", identityAttribute.AttributeDataType, *mgoSession)
    if err != nil{
        response := IdentityAttributesResponse{"error", err.Error(), -1, nil}
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }

    } else{
        response := IdentityAttributesResponse{"success", "", 0, identityAttributes}
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }
    }
}

func getIdentityAttributesByLabel(w http.ResponseWriter, r *http.Request) {

    identityAttribute := StructIdentityAttribute{}

    err := json.NewDecoder(r.Body).Decode(&identityAttribute)
    if (err != nil) {
        w.Write([]byte("JSON Parsing Error"))
    }

    fmt.Println("input object: ", identityAttribute)

    identityAttributes, err := getIdentityAttrbutes(identityAttribute.PubKey, identityAttribute.AttributeLabel, "", *mgoSession)
    if err != nil{
        response := IdentityAttributesResponse{"error", err.Error(), -1, nil}
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }

    } else{
        response := IdentityAttributesResponse{"success", "", 0, identityAttributes}
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }
    }
}

func addIdentityAttribute(w http.ResponseWriter, r *http.Request) {
    identityAttribute := StructIdentityAttribute{}

    err := json.NewDecoder(r.Body).Decode(&identityAttribute)
    if (err != nil) {
        w.Write([]byte("JSON Parsing Error"))
    }

    fmt.Println("input object: ", identityAttribute)


    err = writeToIdentityAttrbutesCollection(identityAttribute, *mgoSession)
    if err != nil{
        response := PostResponse{"error", err.Error(), -1}
        b, err2 := json.Marshal(response);
        if err2 == nil {
            w.Write(b)
        }
    }else{
        response := PostResponse{"success", "", 0}
        b, err2 := json.Marshal(response);
        if err2 == nil {
            w.Write(b)
        }
    }
}

func updateProtectionCode(w http.ResponseWriter, r *http.Request) {
//  handler(w,r, strCollectionIdentities)

    params          := mux.Vars(r)  
    identifier      := params["identifier"]
    protectionCode  := params["protectionCode"]
    pubKey          := params["pubKey"]
    fmt.Printf("protectionCode ==> %v, identifier ==> %v , pubKey==> %v\n \n", protectionCode, identifier, pubKey)

    session := mgoSession.Clone()
    defer session.Close()    
    c := session.DB(AppConfig.DbName).C(strCollectionIdentities)

    err := c.Update(bson.M{"_Identifier": identifier, "_Keys._PrivateKey": pubKey}, bson.M{"$set": bson.M{"_ProtectionCode": protectionCode}})
    if err != nil {
        fmt.Println("Error occurred ", err)
        http.Error(w, "Error occurred while inserting", 400)
    }else{
        fmt.Println("Record Updated")
        w.WriteHeader(200)
    }
}

func createIdentity(w http.ResponseWriter, r *http.Request) {

    identityObj := StructIdentity{}

    err := json.NewDecoder(r.Body).Decode(&identityObj)
    if (err != nil) {
        w.Write([]byte("JSON Parsing Error"))
    }

    fmt.Println("input object: ", identityObj)


    var genKeys StructKeys
    genKeys = generateKeys()


    identityObj.Keys = genKeys
    //idenityObjBinary := StructIdentityBinary{Identifier:identityObj.Identifier, ProtectionCode: identityObj.ProtectionCode, Keys: StructKeysBinary{bson.Binary{0, []byte(identityObj.Keys.PrivateKey)}, bson.Binary{0, []byte(identityObj.Keys.PublicKey)}}}
    idenityObjBinary := StructIdentityBinary{Identifier:identityObj.Identifier, ProtectionCode: identityObj.ProtectionCode, Keys: StructKeysBinary{[]byte(identityObj.Keys.PrivateKey), []byte(identityObj.Keys.PublicKey)}}

    err = writeToIdenityCollection(idenityObjBinary, *mgoSession)

    if err != nil {
        fmt.Println("Error occurred ", err)

        response := PostResponse{"error", err.Error(), -1};
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }

    }else{
        fmt.Println("inserted record ==> identityObj :: ", identityObj)
        w.WriteHeader(200)

        out, err := json.Marshal(identityObj)
        if err != nil {
            panic (err)
        }

        // write the object to blockchain
        writeToBlockChain("createIdentity",identityObj.Keys.PublicKey, string(out))

        response := IdentityResponse{"success", identityObj.Keys.PublicKey}
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }
    }
}



func login(w http.ResponseWriter, r *http.Request) {

    identityObj := StructIdentity{}

    err := json.NewDecoder(r.Body).Decode(&identityObj)
    if (err != nil) {
        w.Write([]byte("JSON Parsing Error"))
    }

    fmt.Println("input object: ", identityObj)

    identities, err := getIdentitity(identityObj.Identifier, identityObj.ProtectionCode, *mgoSession)
    if err != nil{
        response := PostResponse{"error", err.Error(), -1};
        b, err := json.Marshal(response);
        if err == nil {
            w.Write(b)
        }

    } else{

        if(len(identities) > 0){
            fmt.Println("Record found, identities = ", identities)
            w.Header().Set("pubKey", identities[0].Keys.PublicKey)
            w.WriteHeader(200)


            response := IdentityResponse{"success", identities[0].Keys.PublicKey}
            b, err := json.Marshal(response);
            if err == nil {
                w.Write(b)
            }
        }else{
            fmt.Println("Record not found.")
            response := PostResponse{"error", "Identity Not Found", -1};
            b, err := json.Marshal(response);
            if err == nil {
                w.Write(b)
            }
        }
    }

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



    // connect to the database
    //dialInfo, err := mgo.ParseURL(AppConfig.DbConnection)
    //fmt.Printf("%+v\n", dialInfo)

    //if err != nil{

    //    panic(err)
    //}


    fmt.Println("Trying to open DB")

    /*
    //Below part is similar to above.
    tlsConfig := &tls.Config{}
    dialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
        conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
        return conn, err
    }

    fmt.Printf("MongoDB DialInfo %+v\n", dialInfo)
    //session, err := mgo.Dial(AppConfig.DbConnection)
    if err != nil {
        panic(err)
    }

    */
    //session, err1 := mgo.DialWithInfo(dialInfo)
    session, err1 := mgo.Dial(AppConfig.DbConnection)
    defer session.Close()


    if err1 != nil{
        fmt.Println("something bad happened")
        panic(err1)
    }
    fmt.Println("Opened DB")


    // set the global
    mgoSession = session



    // set up our apis
    router := mux.NewRouter()
    router.HandleFunc("/", getReq).Methods("GET")
    router.HandleFunc("/generateSigningKeys", generateSigningKeys).Methods("GET")
    router.HandleFunc("/register", register).Methods("POST");
    router.HandleFunc("/sendTransaction", sendTransaction).Methods("POST")


    // test apis
    router.HandleFunc("/testSigning", testSigning).Methods("POST");
    router.HandleFunc("/testCreateSignedMessage", testCreateSignedMessage).Methods("POST");
    /*
    router.HandleFunc("/createIdentity", createIdentity).Methods("POST")
    router.HandleFunc("/login", login).Methods("POST")
    router.HandleFunc("/addIdentityAttribute", addIdentityAttribute).Methods("POST")
    router.HandleFunc("/getIdentityAttributesByLabel", getIdentityAttributesByLabel).Methods("POST")
    router.HandleFunc("/getIdentityAttributesByDataType", getIdentityAttributesByDataType).Methods("POST")
    */

    // start the server listening
    fmt.Println("Server starting to listen on port = %s", AppConfig.PortNumber)
    if err := http.ListenAndServe(AppConfig.PortNumber, router); err != nil {
        panic(err)
    }

}