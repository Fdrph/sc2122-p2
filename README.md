# Server

Compile:

`javac -cp "lib/*" TrokosServer.java`

Run Server on Windows: 

`java -cp "lib/*;." TrokosServer`

Run Server on Linux:

`java -cp "lib/*:." TrokosServer`

# Client

Compile:

`javac Trokos.java`

Run:

`java Trokos localhost user pass`


O projeto tem a limitação de user=userID ou seja se user for o nome do utilizador entao
dois utilizadores nao podem ter o mesmo nome. Se user=username entao nao pode ter dois
usernames iguais o que é normal, mas o nome real do utilizador nao existe no sistema.
QRcodes nao sao apagados depois de serem pagos.
os dois .jar dentro de lib podem ser postos na raiz do folder (e nao era preciso -cp)
mas fizemos assim porque as úteis ferramentas do vscode funcionam automaticamente 
com jars dentro de /lib