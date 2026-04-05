# EMQX HTTP Authentication/Authorizaion backend

Intended to be used with Node-RED Amazon Alexa and Google Home backend

## Configure

Needs the following environment variables setting to configure MongoDD
client

 - MONGODB_URI=mongodb://root:secret@127.0.0.1:27017
 - MONGODB_DB=assistant
 - MONGODB_COLLECTION=accounts

Command line Arguments

 - `--port`, default `8080`
 - `--passField`, default `mqttPass`
 - `--userField`, default `username`

 ## MongoDB

 It expects the MongoDB Collection to have a field called `username` and
 `mqttPass` which should be in PBKDF2 format, currently on SHA256 hashes
 are supported.