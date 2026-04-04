package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type AuthRequest struct {
	ClientId string `json:"clientId"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ACL struct {
	Permission string `json:"permission"`
	Action     string `json:"action"`
	Topic      string `json:"topic"`
}

type AuthResponse struct {
	Result    string `json:"result"`
	SuperUser bool   `json:"is_superuser"`
	ACL       []ACL  `json:"acl"`
}

type AccountRecord struct {
	Username  string `bson:"username,omitempty"`
	MQTTPass  string `bson:"mqttPass,omitempty"`
	Email     string `bson:"email,omitempty"`
	SuperUser bool   `bson:"superuser,omitempty"`
}

type pbkdf2Hasher struct {
	saltSize     int
	iterations   int
	algorithm    string
	saltEncoding string
	keyLen       int
}

func (h pbkdf2Hasher) getFields(passwordHash string) []string {
	hashSplit := strings.FieldsFunc(passwordHash, func(r rune) bool {
		switch r {
		case '$':
			return true
		default:
			return false
		}
	})
	return hashSplit
}

func (h pbkdf2Hasher) compareBytes(a, b []byte) bool {
	for i, x := range a {
		if b[i] != x {
			return false
		}
	}
	return true
}

func main() {
	uri := os.Getenv("MONGODB_URI")
	db := os.Getenv("MONGODB_DB")
	collection := os.Getenv("MONGODB_COLLECTION")
	fmt.Println(uri, db, collection)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

	coll := client.Database(db).Collection(collection)

	mux := http.NewServeMux()

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1048576)
		var user AuthRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&user)
		if err != nil {
			fmt.Printf("json parse error %s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var result AccountRecord
		err = coll.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)
		if err != nil {
			fmt.Printf("db not found %s\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var hash pbkdf2Hasher
		hashSplit := hash.getFields(result.MQTTPass)
		var (
			hashedPassword []byte
			salt           []byte
			iterations     int
			keyLen         int
		)

		iterations, err = strconv.Atoi(hashSplit[2])
		salt = []byte(hashSplit[3])
		hashedPassword, err = base64.StdEncoding.DecodeString(hashSplit[4])
		keyLen = len(hashedPassword)
		key, err := pbkdf2.Key(sha256.New, user.Password, salt, iterations, keyLen)
		if err != nil {
		}

		var authRes AuthResponse
		if hash.compareBytes(hashedPassword, key) {
			fmt.Print(user.Username, " match\n")
			authRes.Result = "allow"
			authRes.SuperUser = result.SuperUser
			authRes.ACL = []ACL{
				ACL{
					Permission: "allow",
					Action:     "publish",
					Topic:      "status/" + result.Username + "/#",
				},
				ACL{
					Permission: "allow",
					Action:     "publish",
					Topic:      "response/" + result.Username + "/#",
				},
				ACL{
					Permission: "allow",
					Action:     "subscribe",
					Topic:      "command/" + result.Username + "/#",
				},
			}
		} else {
			fmt.Print(user.Username, " fail\n")
			authRes.Result = "deny"
			authRes.SuperUser = false
		}
		json.NewEncoder(w).Encode(authRes)

	})
	log.Print("listening\n")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
