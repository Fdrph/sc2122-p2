import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

public class TrokosServer {

    long BLOCK_N = 0;
    static PrivateKey privK;
    static PublicKey pubK;
    static Signature sig;
    static char[] cipher_pass;

    public static void main(String[] args) {
        int serverPort = 45678;
        if (args.length < 3) {System.out.println("Missing launch arguments");}
        if (args.length == 4) { 
            serverPort = Integer.parseInt(args[0]);
            args = Arrays.copyOfRange(args, 1, args.length);
        }

        cipher_pass = args[0].toCharArray();
        String keyStorePath = args[1];
        String pass_keyStore = args[2];
        
        System.setProperty("javax.net.ssl.keyStore", keyStorePath);
        System.setProperty("javax.net.ssl.keyStorePassword", pass_keyStore);
        TrokosServer server = new TrokosServer();
        
        try {
            // Load keystore, cert and keys
            InputStream keyStoreData = new FileInputStream(keyStorePath);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(keyStoreData, pass_keyStore.toCharArray());
            String alias = ks.aliases().nextElement();
            privK = (PrivateKey) ks.getKey(alias, pass_keyStore.toCharArray());
            Certificate cert = ks.getCertificate(alias);
            pubK = cert.getPublicKey();
            sig = Signature.getInstance("SHA256withRSA");

            Lock dbLock = new ReentrantLock();
            ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
            final SSLServerSocket sSocket = (SSLServerSocket) ssf.createServerSocket(serverPort);

            Runtime.getRuntime().addShutdownHook(new Thread() { public void run() {
                try {sSocket.close();} catch (IOException e) {e.printStackTrace();}
            }});

            File db_dir = new File("db");
            if (!db_dir.exists()) {db_dir.mkdir();}

            if (!new File("db/UserData.crypt").isFile()) {
                encryptFileFromLines("db/UserData.crypt", new ArrayList<String>(), cipher_pass);
            }
            if (!new File("db/UserAccounts.crypt").isFile()) {
                encryptFileFromLines("db/UserAccounts.crypt", new ArrayList<String>(), cipher_pass);
            }
            if (!new File("db/UserGroups.crypt").isFile()) {
                encryptFileFromLines("db/UserGroups.crypt", new ArrayList<String>(), cipher_pass);
            }
            if (!new File("db/pendingPayI.crypt").isFile()) {
                encryptFileFromLines("db/pendingPayI.crypt", new ArrayList<String>(), cipher_pass);
            }
            if (!new File("db/pendingPayG.crypt").isFile()) {
                encryptFileFromLines("db/pendingPayG.crypt", new ArrayList<String>(), cipher_pass);
            }
            if (!new File("db/GroupPayHistory.crypt").isFile()) {
                encryptFileFromLines("db/GroupPayHistory.crypt", new ArrayList<String>(), cipher_pass);
            }
            if (!new File("db/pendingPayQR.crypt").isFile()) {
                encryptFileFromLines("db/pendingPayQR.crypt", new ArrayList<String>(), cipher_pass);
            }

            server.initBlockchain(false);
            
            System.out.println("Listening for clients:");
            while(true) {
                Socket inSoc = sSocket.accept();
                String clientHost = inSoc.getInetAddress().getHostAddress();
                System.out.println("Client Connected: " + clientHost);
                ServerThread newServerThread = server.new ServerThread(inSoc, clientHost, dbLock);
                newServerThread.start();
            }
        } catch (Exception e) {e.printStackTrace();}
    }


    public void initBlockchain(boolean showTransactions) {
        long n_blocks = 0;
        boolean notfound = true;

        while (notfound) {
            n_blocks++;
            // check if file exists
            File bf = new File("db/block_"+n_blocks+".blk");
            if (bf.isFile()) {
                if (!isBlockValid("db/block_"+n_blocks+".blk", n_blocks, showTransactions)) {
                    System.out.println("!!! BLOCKCHAIN VALIDATION ERROR IN BLOCK "+n_blocks+" !!!");
                    return;
                }
            } else {
                notfound = false;
                n_blocks--;
            }
        }
        BLOCK_N = n_blocks;
        if (BLOCK_N == 0) {System.out.println("No previous transaction blockchain found");}
        else {System.out.println("Transaction blockchain succesfully validated");}
    }
    

    public boolean isBlockValid(String blockPath, long b_n, boolean showTransactions) {
        try {
            // check if signature is correct
            ObjectInputStream objin = new ObjectInputStream(new FileInputStream(blockPath));
            SignedObject block = (SignedObject) objin.readObject();
            objin.close();
            Block b = (Block) block.getObject();
            if(!block.verify(pubK, sig)) {return false;}
            if (b_n > 1) {
                // check if hash matches last block's
                byte[] h = b.hash;
                byte[] last_h = getFileHash("db/block_"+(b_n-1)+".blk");
                if (last_h == null) {return false;}
                if (!Arrays.equals(h, last_h)) {return false;}
            }
            if (showTransactions) {
                for (SignedObject to : b.transactions) {System.out.println((String)to.getObject());}
            }
        } catch (Exception e ) {e.printStackTrace(); return false;}
        return true;
    }


    public static byte[] getFileHash(String filePath) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(Paths.get(filePath)));
            return hash;
        } catch (Exception e) {e.printStackTrace(); return null;}
    }


    public static byte[] createQR(String data, int height, int width) {
        try {
            BitMatrix matrix = new MultiFormatWriter().encode(
                new String(data.getBytes("UTF-8"), "UTF-8"),
                BarcodeFormat.QR_CODE, width, height);
    
            ByteArrayOutputStream imgStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", imgStream);
            imgStream.close();
            byte[] imgByteArray = imgStream.toByteArray();
            return imgByteArray;
        } catch (Exception e) {e.printStackTrace();}
        return new byte[0];
    }


    public static void encryptFileFromLines(String fileName, ArrayList<String> lines, char[] pass) {
        try {
            Cipher cipher = makeCipher(pass, fileName, true);
            CipherOutputStream cyph_out = new CipherOutputStream(new FileOutputStream(fileName), cipher);
            String file_string = String.join("|",lines);
            cyph_out.write(file_string.getBytes(StandardCharsets.UTF_8));
            cyph_out.close();
            String p_file_name = fileName.replace(".crypt", ".params");
            Files.write(Paths.get(p_file_name), cipher.getParameters().getEncoded());
        } catch (Exception e) {e.printStackTrace();}
    }

    
    public static ArrayList<String> decryptFileToLines(String fileName, char[] pass) {
        try {
            Cipher cipher = makeCipher(pass, fileName, false);
            CipherInputStream cyph_in = new CipherInputStream(new FileInputStream(fileName), cipher);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            byte[] b = new byte[1024];
            int n_byte_read;
            while ((n_byte_read = cyph_in.read(b))>= 0) {
                baos.write(b, 0, n_byte_read);
            }
            byte[] bytes = baos.toByteArray();
            cyph_in.close();

            String file_string = new String(bytes, StandardCharsets.UTF_8);
            if (file_string.equals("")) {return new ArrayList<String>();}
            ArrayList<String> file_lines = new ArrayList<>(Arrays.asList(file_string.split("\\|")));
            return file_lines;
        } catch (Exception e) {e.printStackTrace(); return new ArrayList<String>();}
    }
    
    
    private static Cipher makeCipher(char[] pass, String fileName, Boolean encrypt) throws Exception {
        byte[] salt = {
            (byte) 0x43, (byte) 0x76, (byte) 0x95, (byte) 0xc7,
            (byte) 0x5b, (byte) 0xd7, (byte) 0x45, (byte) 0x17 
        };

        PBEKeySpec keySpec = new PBEKeySpec(pass, salt, 20);
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey key = kf.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");

        if (encrypt) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            String p_file_name = fileName.replace(".crypt", ".params");
            byte[] params = Files.readAllBytes(Paths.get(p_file_name));
            AlgorithmParameters p = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_128");
            p.init(params);
            cipher.init(Cipher.DECRYPT_MODE, key, p);
        }
        return cipher;
    }


    // One Thread for each client connection
    public class ServerThread extends Thread {

        private Socket clientCon = null;
        private String clientHost = null;
        private Lock dbLock;

        ServerThread(Socket inSoc, String cHost, Lock dblock) {
            clientCon = inSoc; 
            clientHost = cHost;
            dbLock = dblock;
        }
 
        public void run(){
            try {
                final ObjectOutputStream outStream = new ObjectOutputStream(clientCon.getOutputStream());
                final ObjectInputStream inStream = new ObjectInputStream(clientCon.getInputStream());

                // Authenticate the User
                String userID = (String)inStream.readObject();
                Long nonce = new Random().nextLong();
                outStream.writeObject(nonce);
                
                if (!auxUserExists(userID)) {
                    // Create new User
                    outStream.writeObject(false);

                    Certificate clientCert = (Certificate) inStream.readObject();
                    SignedObject signedNonce = (SignedObject) inStream.readObject();

                    Long received = (Long) signedNonce.getObject();
                    Signature s = Signature.getInstance("SHA256withRSA");
                    Boolean sign_matches = signedNonce.verify(clientCert.getPublicKey(), s);
                    
                    if (!nonce.equals(received) || !sign_matches) {
                        failAndDisconnectUser("Couldn't create new user, signature verification failed!", outStream);
                        return;
                    }

                    FileOutputStream fo = new FileOutputStream("db/"+userID+".cert");
                    fo.write(clientCert.getEncoded());
                    fo.close();

                    auxAddLine(userID + ":" + userID+".cert", "db/UserData.crypt");
                    auxAddLine(userID + ":" + "100.0", "db/userAccounts.crypt");

                    outStream.writeObject("SUCCESS:New user created!");
                } else {
                    // User already exists
                    outStream.writeObject(true);

                    SignedObject signedNonce = (SignedObject) inStream.readObject();

                    Certificate userCert = auxGetUserCert(userID);
                    if (userCert == null) {
                        failAndDisconnectUser("Failed to get user certificate", outStream);
                        return;
                    }

                    Signature s = Signature.getInstance("SHA256withRSA");
                    Boolean sign_matches = signedNonce.verify(userCert.getPublicKey(), s);
                    if (!sign_matches) {
                        failAndDisconnectUser("Couldn't authenticate, signature verification failed!", outStream);
                        return;
                    }

                    outStream.writeObject("SUCCESS:User authenticated!");
                }


                // Listen for commands from client
                while(true) {
                    String[] command = (String[])inStream.readObject();
                    String r = "";
                    
                    switch (command[0]){
                        case "b":
                        case "balance":
                            dbLock.lock();
                            r = getBalance(userID);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "m":
                        case "makepayment":
                            dbLock.lock();
                            r = makePayment(userID, command, inStream);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "r":
                        case "requestpayment":
                            dbLock.lock();
                            r = requestPayment(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "v":
                        case "viewrequests":
                            dbLock.lock();
                            r = viewRequests(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "p":
                        case "payrequest":
                            dbLock.lock();
                            r = payRequest(userID, command, inStream);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "n":
                        case "newgroup":
                            dbLock.lock();
                            r = newGroup(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "a":
                        case "addu":
                            dbLock.lock();
                            r = addUser(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "g":
                        case "groups":
                            dbLock.lock();
                            r = viewGroups(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "d":
                        case "dividepayment":
                            dbLock.lock();
                            r = dividePayment(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "s":
                        case "statuspayments":
                            dbLock.lock();
                            r = statusPayments(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "h":
                        case "history":
                            dbLock.lock();
                            r = historyGroup(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "o":
                        case "obtainQRcode":
                            dbLock.lock();
                            obtainQRcode(userID, command, outStream); 
                            dbLock.unlock();
                            break;
                        case "c":
                        case "confirmQRcode":
                            dbLock.lock();
                            r = confirmQRcode(userID, command, inStream);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "getrequest":
                            dbLock.lock();
                            r = getRequestInfo(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        case "getrequestQR":
                            dbLock.lock();
                            r = getRequestInfoQR(userID, command);
                            dbLock.unlock();
                            outStream.writeObject(r);
                            break;
                        default:
                            outStream.writeObject("Command is wrong!");
                    }
                }

            } catch (Exception e) {
                if (e instanceof EOFException) {
                    System.out.println("Client Disconnected:" + clientHost);
                } else {e.printStackTrace();}
            }
            try {clientCon.close();} catch (IOException e) {e.printStackTrace();}
        }


        // Create pending QR code payment for this client,
        // deals with sending image over to client aswell
        private void obtainQRcode(String clientID, String[] args, ObjectOutputStream outStream) {
            try{
            if (args.length != 2) {
                outStream.writeObject("ERROR");
                outStream.writeObject("Missing or wrong arguments");
                return;
            }
            String amount = args[1];
            String qrcodeID = UUID.randomUUID().toString();
            String entry = clientID+":"+amount+":"+qrcodeID;
            auxAddLine(entry, "db/pendingPayQR.crypt");
            outStream.writeObject("SUCCESS");
            byte[] img = createQR(qrcodeID, 350, 350);
            String imgstr = Base64.getEncoder().encodeToString(img);
            outStream.writeObject(imgstr);
            outStream.writeObject(qrcodeID);
            } catch (Exception e) {e.printStackTrace();}
        }


        private String getRequestInfoQR(String clientID, String[] args) {
            if (args.length != 2) {return "ERROR: Missing or wrong arguments";}
            String reqID = args[1];
            String entry = auxGetPendGroup(reqID, "db/pendingPayQR.crypt");
            if (entry.equals("")) {return "ERROR: QRCode given does not exist";}
            String[] e = entry.split(":");
            String receiver = e[0];
            String amount = e[1];
            if (receiver.equals(clientID)) {return "ERROR: You cannot pay yourself!";}
            return receiver+":"+amount;
        }


        // Remove pending qrcode payment and pay it
        private String confirmQRcode(String clientID, String[] args, ObjectInputStream inStream) {
            try{
                SignedObject transaction = (SignedObject) inStream.readObject();
                if (args.length != 2) {return "ERROR: Missing or wrong arguments";}
                String qrcode = args[1];
                String entry = auxGetPendGroup(qrcode, "db/pendingPayQR.crypt");
                if (entry.equals("")) {return "ERROR: QRCode given does not exist";}
                String[] e = entry.split(":");
                String receiver = e[0];
                String amount = e[1];
                if (Double.parseDouble(amount) > Double.parseDouble(getBalance(clientID))) {
                    return "ERROR: amount exceeds your funds";
                }
                if (!validateTransaction(transaction)) {
                    return "ERROR: Signature verification failed!";
                }
                transferBalance(clientID, receiver, amount);
                auxRemoveLine(entry,  "db/pendingPayQR.crypt");
                addToBlockChain(transaction);

                return "Payment made to "+receiver+" of "+amount+" successfully";
            } catch (Exception e) {e.printStackTrace(); return "ERROR: Exception error";}
        }


        // Return the user's account balance
        private String getBalance(String user) {
            String balance = "";
            try{
                ArrayList<String> lines = decryptFileToLines("db/UserAccounts.crypt", cipher_pass);
                balance = lines.stream()
                    .filter(l -> l.split(":")[0]
                    .equals(user))
                    .findFirst().orElse("");
                balance = balance.split(":")[1];
            } catch(Exception e) {e.printStackTrace();}
            return balance;
        }


        // Transfer amount from client to another user
        private String makePayment(String clientID, String[] args, ObjectInputStream inStream) {
            try{
                SignedObject transaction = (SignedObject) inStream.readObject();
                if (args.length != 3) {return "Missing or wrong arguments";}
                String userID = args[1];
                String amount = args[2];

                if (!auxUserExists(userID)) {
                    return "ERROR: User doesn't exist";
                }
                if (Double.parseDouble(amount) > Double.parseDouble(getBalance(clientID))) {
                    return "ERROR: Amount exceeds your funds";
                }
                if (!validateTransaction(transaction)) {
                    return "ERROR: Signature verification failed!"; 
                }

                transferBalance(clientID, userID, amount);
                addToBlockChain(transaction);

                return "Payment made successfully";
            } catch (Exception e) {e.printStackTrace(); return "ERROR: Exception error";}
        }

        
        // Create payment request from client to user
        private String requestPayment(String clientID, String[] args) {
            if (args.length != 3) {return "Missing or wrong arguments";}
            String userID = args[1];
            String amount = args[2];
            Double nr = Double.parseDouble(amount);
            if (!auxUserExists(userID)) {return "ERROR: User doesn't exist";}
            if (clientID.equals(userID)) {return "ERROR: You can't create a request for yourself!";}

            String uID = UUID.randomUUID().toString();
            String line = userID+":"+clientID+":"+nr.toString()+":"+ uID;
            auxAddLine(line, "db/pendingPayI.crypt");
            return "Request created sucessfully";
        }


        // View payment requests pending for the client
        private String viewRequests(String clientID, String[] args) {
            if (args.length != 1) {return "Missing or wrong arguments";}
            String nl = System.lineSeparator();
            String response = "";

            List<String> requests = auxGetLinesByUser(clientID, "db/pendingPayI.crypt");
            if (requests.isEmpty()) {return "No pending payment requests found";}
            for (String r : requests) {
                String[] s = r.split(":");
                response +=  "User: " + s[1] + nl;
                response += "Amount: " + s[2] + nl;
                response += "requestID: " + s[3] + nl + nl;
            }
            return response;
        }


        private String getRequestInfo(String clientID, String[] args) {
            if (args.length != 2) {return "ERROR: Missing or wrong arguments";}
            String reqID = args[1];
            List<String> requests = auxGetLinesByUser(clientID, "db/pendingPayI.crypt");
            if (requests.isEmpty()) {return "ERROR: You have no pending payments!";}
            for (String request: requests){
                String[] s = request.split(":");
                if (s[0].equals(clientID) && s[3].equals(reqID)) {
                    Double amount = Double.parseDouble(s[2]);
                    return s[1]+":"+amount.toString();
                }
            }
            return "ERROR: You have no pending payments with given ID";
        }


        // Pay the request with the ID given, we know it exists already
        private String payRequest(String clientID, String[] args, ObjectInputStream inStream) {
            try {
                SignedObject transaction = (SignedObject) inStream.readObject();
                if (args.length != 2) {return "Missing or wrong arguments";}
                String reqID  = args[1];
                Double amount = 0.0;
                List<String> requests = auxGetLinesByUser(clientID, "db/pendingPayI.crypt");
                for (String request: requests){
                    String[] s = request.split(":");
                    if (s[0].equals(clientID) && s[3].equals(reqID)) {
                        amount = Double.parseDouble(s[2]);
                        if ( amount > Double.parseDouble(getBalance(clientID)) ) {
                            return "ERROR: Amount exceeds your funds";
                        }
                        if (!validateTransaction(transaction)) {
                            return "ERROR: Signature verification failed!";
                        }
                        transferBalance(clientID, s[1], amount.toString());
                        auxRemoveLine(request, "db/pendingPayI.crypt");
                        addToBlockChain(transaction);
                        // update group payment system if needed
                        if (s.length == 5) {updateGroupPay(s[4]);}

                        return "Payment made successfully";
                    }
                }
                return "ERROR: This should never be reached! app is buggy!";
            } catch (Exception e) {e.printStackTrace(); return "ERROR: Exception error";}
        }


        // Check if group payment has no more pending pay requests 
        private void updateGroupPay(String groupPayID) {
            List<String> pending = auxGetPendByGroupPendID(groupPayID, "db/pendingPayI.crypt");
            if (pending.size() == 0) {
             String g = auxGetPendGroup(groupPayID, "db/pendingPayG.crypt");
             auxRemoveLine(g, "db/pendingPayG.crypt");
             auxAddLine(g,  "db/GroupPayHistory.crypt");
            }
        }


        // Create a new group with the client as owner
        private String newGroup(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String groupID = args[1];
            List<String> groups = auxGetLinesByUser(clientID, "db/UserGroups.crypt");
            for (String r : groups) {
                String[] s = r.split(":");
                if (s[1].equals(groupID)) {return "ERROR: group already exists";}
            }
            String g = clientID+":"+groupID;
            auxAddLine(g, "db/UserGroups.crypt");
            return "Group created";
        }


        // Add given user to given group with the client as owner
        private String addUser(String clientID, String[] args) {
            if (args.length != 3) {return "Missing or wrong arguments";}
            String userID = args[1];
            String groupID = args[2];
            if (!auxUserExists(userID)) {return "ERROR: User doesn't exist";}
            if (clientID.equals(userID)) {return "ERROR: Can't add yourself to your group";}

            String group = auxGetGroup(groupID, "db/UserGroups.crypt");
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}
            for (String u : s) {
                if (u.equals(userID)) {return "ERROR: User already exists in group";}
            }
            String newLine = group + ":" + userID;
            auxReplaceLine(group, newLine, "db/UserGroups.crypt");
            return "Added user to group";
        }


        // Shows the groups client owns and groups he's in
        private String viewGroups(String clientID, String[] args) {
            if (args.length != 1) {return "Missing or wrong arguments";}
            String nl = System.lineSeparator();
            String response = "-Groups you own:" + nl + nl;

            List<String> owned = auxGetLinesByUser(clientID, "db/UserGroups.crypt");
            if (owned.size() == 0) {response += "You don't own any groups"+nl;}
            else {
                for (String g : owned) {
                    String[] f = g.split(":");
                    response += "*Group " + f[1] + nl;
                    for (int i=2;i<f.length;i++) {
                        response += f[i] + nl;
                    }
                    response += nl;
                }
            }
            response += nl + "-Groups you are in:"+ nl + nl;
            List<String> in = auxGetGroupsByUser(clientID, "db/UserGroups.crypt");
            if (in.size() == 0) {response += "You aren't in any groups";}
            else {
                for (String g : in) {
                    String[] f = g.split(":");
                    response += "*Group " + f[1] + " | " + "Owner: " + f[0] + nl;
                    for (int i=2;i<f.length;i++) {
                        response += f[i] + nl;
                    }
                    response += nl;
                }
            }
            return response;
        }

        
        // Create a group payment request
        private String dividePayment(String clientID, String[] args) {
            if (args.length != 3) {return "Missing or wrong arguments";}
            String groupID = args[1];
            String amount = args[2];
            Double nr = Double.parseDouble(amount);
            String group = auxGetGroup(groupID, "db/UserGroups.crypt");
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}

            String gUID = UUID.randomUUID().toString();
            String request = groupID+":"+amount+":"+gUID;
            auxAddLine(request, "db/pendingPayG.crypt");
            for (int i=2;i<s.length;i++) {
                String mUID = UUID.randomUUID().toString();
                String member = s[i];
                String indivRequest = member+":"+clientID+":"+Double.toString(nr/(s.length-2))+":"+mUID+":"+gUID;
                auxAddLine(indivRequest, "db/pendingPayI.crypt");
            }
            return "Created payment requests sucessfully";
        }


        // Show status of payment requests for certain group
        private String statusPayments(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String groupID = args[1];
            String response = "";
            String nl = System.lineSeparator();
            String group = auxGetGroup(groupID, "db/UserGroups.crypt");
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}

            List<String> pending = auxGetLinesByUser(groupID,  "db/pendingPayG.crypt");
            if (pending.size() == 0) {return "No pending payments on this group";}
            for (String pp : pending) {
                String[] el = pp.split(":");
                response += "ID: " + el[2] + nl;
                response += "Amount: " + el[1] + nl;
                List<String> l = auxGetPendByGroupPendID(el[2], "db/pendingPayI.crypt");
                for (String k : l) {
                    String[] kk = k.split(":");
                    response += kk[0] + nl;
                }
                response += nl;
            }
            return response;
        }


        // Show history of group payments for certain group
        private String historyGroup(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String groupID = args[1];
            String response = "";
            String nl = System.lineSeparator();
            String group = auxGetGroup(groupID, "db/UserGroups.crypt");
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}

            List<String> pending = auxGetLinesByUser(groupID,  "db/GroupPayHistory.crypt");
            if (pending.size() == 0) {return "No payment history on this group";}
            for (String pp : pending) {
                String[] el = pp.split(":");
                response += "ID: " + el[2] + nl;
                response += "Amount: " + el[1] + nl;
                response += nl;
            }
            return response;
        }
        

        // Add amount to the user's balance
        private void addBalance(String user, String amount) {
            String oldBalance = getBalance(user);
            Double newBalance = Double.parseDouble(oldBalance) + Double.parseDouble(amount);
            String oldLine = user+":"+oldBalance;
            String newLine = user+":"+Double.toString(newBalance);
            auxReplaceLine(oldLine, newLine, "db/UserAccounts.crypt");
        }


        // Remove amount from the user's balance
        private void removeBalance(String user, String amount) {
            String oldBalance = getBalance(user);
            Double newBalance = Double.parseDouble(oldBalance) - Double.parseDouble(amount);
            String oldLine = user+":"+oldBalance;
            String newLine = user+":"+Double.toString(newBalance);
            auxReplaceLine(oldLine, newLine, "db/UserAccounts.crypt");
        }

        // Transfer amount of balance from user1 to user2
        private void transferBalance(String user1, String user2, String amount) {
            try{
                removeBalance(user1, amount);
                addBalance(user2, amount);
            } catch (Exception e) {e.printStackTrace();}
        }


        /* ---------------------- AUX FUNCTIONS ---------------------- */

        private Boolean auxUserExists(String user) {
            try{
                ArrayList<String> lines = decryptFileToLines("db/UserData.crypt", cipher_pass);
                return lines.stream().anyMatch(l -> user.equals(l.split(":")[0]));
            } catch(Exception e) {
                e.printStackTrace();
                return false;
            }
        }
        
        private void auxReplaceLine(String oldL, String newL, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).equals(oldL)) {
                        lines.set(i, newL);
                        break;
                    }
                }
                encryptFileFromLines(Path.toString(), lines, cipher_pass);
            } catch (Exception e) {e.printStackTrace();}
        }
        
        private void auxRemoveLine(String line, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).equals(line)) {
                        lines.remove(i);
                        break;
                    }
                }
                encryptFileFromLines(Path.toString(), lines, cipher_pass);
            } catch (Exception e) {e.printStackTrace();}
        }
        
        private void auxAddLine(String line, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path.toString(), cipher_pass);
                lines.add(line);
                encryptFileFromLines(Path, lines, cipher_pass);
            } catch (Exception e) {e.printStackTrace();}
        }

        private List<String> auxGetLinesByUser(String user, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                ArrayList<String> filteredLines = new ArrayList<String>();
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).split(":")[0].equals(user)) {
                        filteredLines.add(lines.get(i));
                    }
                }
                return filteredLines;
            } catch (Exception e) {e.printStackTrace();}
            return new ArrayList<String>();
        }

        private String auxGetGroup(String groupID, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).split(":")[1].equals(groupID)) {
                        return lines.get(i);
                    }
                }
            } catch (Exception e) {e.printStackTrace();}
            return "";
        }

        private String auxGetPendGroup(String groupPendID, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).split(":")[2].equals(groupPendID)) {
                        return lines.get(i);
                    }
                }
            } catch (Exception e) {e.printStackTrace();}
            return "";
        }

        private List<String> auxGetGroupsByUser(String user, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                ArrayList<String> filteredLines = new ArrayList<String>();
                for (int i = 0; i < lines.size(); i++) {
                    ArrayList<String> strlist  = new ArrayList<String>(Arrays.asList(lines.get(i).split(":")));
                    strlist.remove(0);
                    strlist.remove(0);
                    if (strlist.contains(user)) {
                        filteredLines.add(lines.get(i));
                    }
                }
                return filteredLines;
            } catch (Exception e) {e.printStackTrace();}
            return new ArrayList<String>();
        }

        private List<String> auxGetPendByGroupPendID(String id, String Path) {
            try {
                ArrayList<String> lines = decryptFileToLines(Path, cipher_pass);
                ArrayList<String> filteredLines = new ArrayList<String>();
                for (int i = 0; i < lines.size(); i++) {
                    List<String> strlist  = new ArrayList<String>(Arrays.asList(lines.get(i).split(":")));
                    if (strlist.size() == 5 && strlist.get(4).equals(id)) {
                        filteredLines.add(lines.get(i));
                    }
                }
                return filteredLines;
            } catch (Exception e) {e.printStackTrace();}
            return new ArrayList<String>();
        }

        private Certificate auxGetUserCert(String userID) {
            try{
                ArrayList<String> lines = decryptFileToLines("db/UserData.crypt", cipher_pass);
                String userdata = lines.stream()
                    .filter(l -> l.split(":")[0]
                    .equals(userID))
                    .findFirst().orElse("");
                String certName = userdata.split(":")[1];

                FileInputStream cis = new FileInputStream("db/"+certName);
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                return cf.generateCertificate(cis);
            } catch (Exception e) {e.printStackTrace(); return null;}
        }

        private void failAndDisconnectUser(String message, ObjectOutputStream outStream) {
            try{
                outStream.writeObject("FAILURE:"+message);
                clientCon.close();
                System.out.println("Client Disconnected: " + clientHost);
            } catch (Exception e) {e.printStackTrace();}
        }

        // String transaction = "receiver:amount:sender"
        private Boolean validateTransaction(SignedObject transaction) {
            try {
                String ts = (String) transaction.getObject();
                String client = ts.split(":")[2];
                Certificate userCert = auxGetUserCert(client);
                if (userCert == null) {return false;}
                if (!transaction.verify(userCert.getPublicKey(), sig)) {return false;}
            } catch (Exception e) {e.printStackTrace(); return false;}
            return true;
        }

        private void addToBlockChain(SignedObject transaction) {
            try {
                if (BLOCK_N == 0) {
                    // create first blockchain file if none exists
                    Block b1 = new Block( new byte[32], 1, new ArrayList<>(Arrays.asList(transaction)));
                    SignedObject block_1 = new SignedObject(b1, privK, sig);
                    ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("db/block_1.blk"));
                    out.writeObject(block_1);
                    out.close();
                    BLOCK_N++;
                } else {
                    // open current latest block
                    ObjectInputStream in = new ObjectInputStream(new FileInputStream("db/block_"+BLOCK_N+".blk"));
                    SignedObject block = (SignedObject) in.readObject();
                    in.close();
                    Block b = (Block) block.getObject();

                    if (b.n_transactions < 5) {
                        // add latest transaction to block
                        b.addTransaction(transaction);
                        // sign it and save it
                        SignedObject b_signed = new SignedObject(b, privK, sig);
                        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("db/block_"+BLOCK_N+".blk"));
                        out.writeObject(b_signed);
                        out.close();
                    } else {
                        BLOCK_N++;
                        byte[] last_h = getFileHash("db/block_"+(BLOCK_N-1)+".blk");
                        // create new block with last hash as header and first transaction
                        Block new_b = new Block(last_h, BLOCK_N, new ArrayList<>(Arrays.asList(transaction)));
                        // sign it and save it
                        SignedObject b_signed = new SignedObject(new_b, privK, sig);
                        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("db/block_"+BLOCK_N+".blk"));
                        out.writeObject(b_signed);
                        out.close();
                    }
                }
            } catch (Exception e) {e.printStackTrace();}
        }
    }
}

final class Block implements Serializable {
        
    private static final long serialVersionUID = 1L;
    
    byte[] hash;
    long b_number;
    long n_transactions;
    List<SignedObject> transactions;

    Block(byte[] hash, long b_n, List<SignedObject> transactions) {
        this.hash = hash;
        this.b_number = b_n;
        this.n_transactions = 1;
        this.transactions = transactions;
    }

    public void addTransaction(SignedObject tr) {
        transactions.add(tr);
        n_transactions++;
    }
}