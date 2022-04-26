# Server

Compile:

`javac -cp "lib/*" TrokosServer.java`

Run Server on Windows: 

`java -cp "lib/*;." TrokosServer trokos-db "k_server/keystore.server" sc2122-trokos`

Run Server on Linux:

`java -cp "lib/*:." TrokosServer trokos-db "k_server/keystore.server" sc2122-trokos`

# Client

Compile:

`javac Trokos.java`

Run:

`java Trokos localhost "k_client/truststore.client" "k_client/keystore.client" sc2122-client userID`


