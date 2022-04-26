import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

public class TrokosServer {

    public static void main(String[] args) {
        int serverPort = 45678;
        if (args.length < 3) {System.out.println("Missing launch arguments");}
        if (args.length == 4) { 
            serverPort = Integer.parseInt(args[0]);
            args = Arrays.copyOfRange(args, 1, args.length);
        }

        String cipher_pass = args[0];
        String keystore = args[1];
        String pass_keystore = args[2];
        
        System.setProperty("javax.net.ssl.keyStore", keystore);
        System.setProperty("javax.net.ssl.keyStorePassword", pass_keystore);
        TrokosServer server = new TrokosServer();

        try {
            ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
            final SSLServerSocket sSocket = (SSLServerSocket) ssf.createServerSocket(serverPort);

            Runtime.getRuntime().addShutdownHook(new Thread() { public void run() {
                try {sSocket.close();} catch (IOException e) {e.printStackTrace();}
            }});

            File userData = new File("db/UserData.txt");
            File userAccounts = new File("db/UserAccounts.txt");
            File userGroups = new File("db/UserGroups.txt");
            File pendingPayI = new File("db/pendingPayI.txt");
            File pendingPayG = new File("db/pendingPayG.txt");
            File groupPayHistory = new File("db/GroupPayHistory.txt");
            File pendingPayQR = new File("db/pendingPayQR.txt");
            userData.createNewFile();
            userAccounts.createNewFile();
            userGroups.createNewFile();
            pendingPayI.createNewFile();
            pendingPayG.createNewFile();
            groupPayHistory.createNewFile();
            pendingPayQR.createNewFile();
            while(true) {
                Socket inSoc = sSocket.accept();
                String clientHost = inSoc.getInetAddress().getHostAddress();
                System.out.println("Client Connected: " + clientHost);
                ServerThread newServerThread = server.new ServerThread(inSoc, clientHost);
                newServerThread.start();
            }
        } catch (Exception e) {e.printStackTrace();}
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

    // One Thread for each client connection
    public class ServerThread extends Thread {

        private Socket clientCon = null;
        private String clientHost = null;

        ServerThread(Socket inSoc, String cHost) {clientCon = inSoc; clientHost = cHost;}
 
        public void run(){
            try {
                ObjectOutputStream outStream = new ObjectOutputStream(clientCon.getOutputStream());
                ObjectInputStream inStream = new ObjectInputStream(clientCon.getInputStream());

                String user = (String)inStream.readObject();
                String passwd = (String)inStream.readObject();
             
                // Authenticate the user and create user account if needed
                Path p = Paths.get("db/UserData.txt");
                Boolean passwdFound = Files.lines(p).anyMatch(l -> l.equals(user + ":" + passwd));
                if (!auxUserExists(user)) {
                    PrintWriter writer = new PrintWriter(new FileWriter("db/UserData.txt",true));
                    writer.println(user + ":" + passwd);
                    writer.close();

                    PrintWriter balWriter = new PrintWriter(new FileWriter("db/UserAccounts.txt",true));
                    balWriter.println(user + ":" + "100.0");
                    balWriter.close();

                    outStream.writeObject("Success:New user created!");
                } else if (passwdFound) {
                    outStream.writeObject("Success:User authenticated!");
                } else {
                    outStream.writeObject("Failure:Wrong password!");
                    clientCon.close();
                    System.out.println("Client Disconnected:" + clientHost);
                    return;
                }

                // Listen for commands from client
                while(true) {
                    String[] command = (String[])inStream.readObject();
                    String r = "";

                    switch (command[0]){
                        case "b":
                        case "balance":
                            r = getBalance(user);
                            outStream.writeObject(r);
                            break;
                        case "m":
                        case "makepayment":
                            r = makePayment(user, command);
                            outStream.writeObject(r);
                            break;
                        case "r":
                        case "requestpayment":
                            r = requestPayment(user, command);
                            outStream.writeObject(r);
                            break;
                        case "v":
                        case "viewrequests":
                            r = viewRequests(user, command);
                            outStream.writeObject(r);
                            break;
                        case "p":
                        case "payrequest":
                            r = payRequest(user, command);
                            outStream.writeObject(r);
                            break;
                        case "n":
                        case "newgroup":
                            r = newGroup(user, command);
                            outStream.writeObject(r);
                            break;
                        case "a":
                        case "addu":
                            r = addUser(user, command);
                            outStream.writeObject(r);
                            break;
                        case "g":
                        case "groups":
                            r = viewGroups(user, command);
                            outStream.writeObject(r);
                            break;
                        case "d":
                        case "dividepayment":
                            r = dividePayment(user, command);
                            outStream.writeObject(r);
                            break;
                        case "s":
                        case "statuspayments":
                            r = statusPayments(user, command);
                            outStream.writeObject(r);
                            break;
                        case "h":
                        case "history":
                            r = historyGroup(user, command);
                            outStream.writeObject(r);
                            break;
                        case "o":
                        case "obtainQRcode":
                            obtainQRcode(user, command, outStream); 
                            break;
                        case "c":
                        case "confirmQRcode":
                            r = confirmQRcode(user, command);
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
            auxAddLine(entry, Paths.get("db/pendingPayQR.txt"));
            outStream.writeObject("SUCCESS");
            byte[] img = createQR(qrcodeID, 350, 350);
            String imgstr = Base64.getEncoder().encodeToString(img);
            outStream.writeObject(imgstr);
            outStream.writeObject(qrcodeID);
            } catch (Exception e) {e.printStackTrace();}
        }


        // Remove pending qrcode payment and pay it
        private String confirmQRcode(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String qrcode = args[1];
            String entry = auxGetPendGroup(qrcode, Paths.get("db/pendingPayQR.txt"));
            if (entry.equals("")) {return "ERROR: QRCode given does not exist";}
            String[] e = entry.split(":");
            String userid = e[0];
            String amount = e[1];
            if (userid.equals(clientID)) {return "ERROR: You cannot pay yourself!";}
            auxRemoveLine(entry,  Paths.get("db/pendingPayQR.txt"));
            if (Double.parseDouble(amount) > Double.parseDouble(getBalance(clientID))) {
                return "ERROR: amount exceeds your funds";
            }
            removeBalance(clientID, amount);
            addBalance(userid, amount);
            return "Payment made to "+userid+" of "+amount+" successfully";
        }


        // Return the user's account balance
        private String getBalance(String user) {
            String balance = "";
            try{
                Path p = Paths.get("db/UserAccounts.txt");
                balance = Files.lines(p)
                    .filter(l -> l.split(":")[0]
                    .equals(user))
                    .findFirst().orElse("");
                balance = balance.split(":")[1];
            } catch(IOException e) {e.printStackTrace();}
            return balance;
        }


        // Transfer amount from client to another user
        private String makePayment(String clientID, String[] args) {
            if (args.length != 3) {return "Missing or wrong arguments";}
            String userID = args[1];
            String amount = args[2];

            if (!auxUserExists(userID)) {
                return "ERROR: User doesn't exist";
            }
            if (Double.parseDouble(amount) > Double.parseDouble(getBalance(clientID))) {
                return "ERROR: amount exceeds your funds";
            }

            removeBalance(clientID, amount);
            addBalance(userID, amount);
            return "Payment made successfully";
        }

        
        // Create payment request from client to user
        private String requestPayment(String clientID, String[] args) {
            if (args.length != 3) {return "Missing or wrong arguments";}
            String userID = args[1];
            String amount = args[2];
            Double nr = Double.parseDouble(amount);
            if (!auxUserExists(userID)) {return "ERROR: User doesn't exist";}

            String uID = UUID.randomUUID().toString();
            String line = userID+":"+clientID+":"+nr.toString()+":"+ uID;
            auxAddLine(line, Paths.get("db/pendingPayI.txt"));
            return "Request created sucessfully";
        }


        // View payment requests pending for the client
        private String viewRequests(String clientID, String[] args) {
            if (args.length != 1) {return "Missing or wrong arguments";}
            String nl = System.lineSeparator();
            String response = "";

            List<String> requests = auxGetLinesByUser(clientID, Paths.get("db/pendingPayI.txt"));
            if (requests.isEmpty()) {return "No pending payment requests found";}
            for (String r : requests) {
                String[] s = r.split(":");
                response +=  "User: " + s[1] + nl;
                response += "Amount: " + s[2] + nl;
                response += "requestID: " + s[3] + nl + nl;
            }
            return response;
        }


        // Pay the request with the ID given
        private String payRequest(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String reqID  = args[1];
            Double amount = 0.0;
            List<String> requests = auxGetLinesByUser(clientID, Paths.get("db/pendingPayI.txt"));
            if (requests.isEmpty()) {return "ERROR: No pending payment with given ID exists";}
            for (String request: requests){
                String[] s = request.split(":");
                if (s[0].equals(clientID) && s[3].equals(reqID)) {
                    amount = Double.parseDouble(s[2]);
                    if ( amount > Double.parseDouble(getBalance(clientID)) ) {
                        return "ERROR: amount exceeds your funds";
                    }
                    removeBalance(clientID, amount.toString());
                    addBalance(s[1], amount.toString());
                    auxRemoveLine(request, Paths.get("db/pendingPayI.txt"));
                    // check for group payments here
                    if (s.length == 5) {updateGroupPay(s[4]);}
                    return "Payment made successfully";
                }
            }
            return "ERROR: You aren't part of this request";
        }


        // Check if group payment has no more pending pay requests 
        private void updateGroupPay(String groupPayID) {
            List<String> pending = auxGetPendByGroupPendID(groupPayID, Paths.get("db/pendingPayI.txt"));
            if (pending.size() == 0) {
             String g = auxGetPendGroup(groupPayID, Paths.get("db/pendingPayG.txt"));
             auxRemoveLine(g, Paths.get("db/pendingPayG.txt"));
             auxAddLine(g,  Paths.get("db/GroupPayHistory.txt"));
            }
        }


        // Create a new group with the client as owner
        private String newGroup(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String groupID = args[1];
            List<String> groups = auxGetLinesByUser(clientID, Paths.get("db/UserGroups.txt"));
            for (String r : groups) {
                String[] s = r.split(":");
                if (s[1].equals(groupID)) {return "ERROR: group already exists";}
            }
            String g = clientID+":"+groupID;
            auxAddLine(g, Paths.get("db/UserGroups.txt"));
            return "Group created";
        }


        // Add given user to given group with the client as owner
        private String addUser(String clientID, String[] args) {
            if (args.length != 3) {return "Missing or wrong arguments";}
            String userID = args[1];
            String groupID = args[2];
            if (!auxUserExists(userID)) {return "ERROR: User doesn't exist";}
            if (clientID.equals(userID)) {return "ERROR: Can't add yourself to your group";}

            String group = auxGetGroup(groupID, Paths.get("db/UserGroups.txt"));
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}
            for (String u : s) {
                if (u.equals(userID)) {return "ERROR: User already exists in group";}
            }
            String newLine = group + ":" + userID;
            auxReplaceLine(group, newLine, Paths.get("db/UserGroups.txt"));
            return "Added user to group";
        }


        // Shows the groups client owns and groups he's in
        private String viewGroups(String clientID, String[] args) {
            if (args.length != 1) {return "Missing or wrong arguments";}
            String nl = System.lineSeparator();
            String response = "-Groups you own:" + nl + nl;

            List<String> owned = auxGetLinesByUser(clientID, Paths.get("db/UserGroups.txt"));
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
            List<String> in = auxGetGroupsByUser(clientID, Paths.get("db/UserGroups.txt"));
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
            String group = auxGetGroup(groupID, Paths.get("db/UserGroups.txt"));
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}

            String gUID = UUID.randomUUID().toString();
            String request = groupID+":"+amount+":"+gUID;
            auxAddLine(request, Paths.get("db/pendingPayG.txt"));
            for (int i=2;i<s.length;i++) {
                String mUID = UUID.randomUUID().toString();
                String member = s[i];
                String indivRequest = member+":"+clientID+":"+Double.toString(nr/(s.length-2))+":"+mUID+":"+gUID;
                auxAddLine(indivRequest, Paths.get("db/pendingPayI.txt"));
            }
            return "Created payment requests sucessfully";
        }


        // Show status of payment requests for certain group
        private String statusPayments(String clientID, String[] args) {
            if (args.length != 2) {return "Missing or wrong arguments";}
            String groupID = args[1];
            String response = "";
            String nl = System.lineSeparator();
            String group = auxGetGroup(groupID, Paths.get("db/UserGroups.txt"));
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}

            List<String> pending = auxGetLinesByUser(groupID,  Paths.get("db/pendingPayG.txt"));
            if (pending.size() == 0) {return "No pending payments on this group";}
            for (String pp : pending) {
                String[] el = pp.split(":");
                response += "ID: " + el[2] + nl;
                response += "Amount: " + el[1] + nl;
                List<String> l = auxGetPendByGroupPendID(el[2], Paths.get("db/pendingPayI.txt"));
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
            String group = auxGetGroup(groupID, Paths.get("db/UserGroups.txt"));
            if (group.equals("")) {return "ERROR: Group doesn't exist";}
            String[] s = group.split(":");
            if (!s[0].equals(clientID)) {return "ERROR: You are not the group owner";}

            List<String> pending = auxGetLinesByUser(groupID,  Paths.get("db/GroupPayHistory.txt"));
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
            auxReplaceLine(oldLine, newLine, Paths.get("db/UserAccounts.txt"));
        }


        // Remove amount from the user's balance
        private void removeBalance(String user, String amount) {
            String oldBalance = getBalance(user);
            Double newBalance = Double.parseDouble(oldBalance) - Double.parseDouble(amount);
            String oldLine = user+":"+oldBalance;
            String newLine = user+":"+Double.toString(newBalance);
            auxReplaceLine(oldLine, newLine, Paths.get("db/UserAccounts.txt"));
        }


        /* ---------------------- AUX FUNCTIONS ---------------------- */

        private Boolean auxUserExists(String user) {
            try{
                return Files.lines(Paths.get("db/UserData.txt")).anyMatch(l -> user.equals(l.split(":")[0]));
            } catch(Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        private void auxReplaceLine(String oldL, String newL, Path Path) {
            try {
                List<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).equals(oldL)) {
                        lines.set(i, newL);
                        break;
                    }
                }
                Files.write(Path, lines, StandardCharsets.UTF_8);
            } catch (Exception e) {e.printStackTrace();}
        }

        private void auxRemoveLine(String line, Path Path) {
            try {
                List<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).equals(line)) {
                        lines.remove(i);
                        break;
                    }
                }
                Files.write(Path, lines, StandardCharsets.UTF_8);
            } catch (Exception e) {e.printStackTrace();}
        }

        private void auxAddLine(String line, Path Path) {
            try {
                PrintWriter w = new PrintWriter(new FileWriter(Path.toString(),true));
                w.println(line);
                w.close();
            } catch (Exception e) {e.printStackTrace();}
        }

        private List<String> auxGetLinesByUser(String user, Path Path) {
            try {
                ArrayList<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
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

        private String auxGetGroup(String groupID, Path Path) {
            try {
                ArrayList<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).split(":")[1].equals(groupID)) {
                        return lines.get(i);
                    }
                }
            } catch (Exception e) {e.printStackTrace();}
            return "";
        }

        private String auxGetPendGroup(String groupPendID, Path Path) {
            try {
                ArrayList<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).split(":")[2].equals(groupPendID)) {
                        return lines.get(i);
                    }
                }
            } catch (Exception e) {e.printStackTrace();}
            return "";
        }

        private List<String> auxGetGroupsByUser(String user, Path Path) {
            try {
                ArrayList<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
                ArrayList<String> filteredLines = new ArrayList<String>();
                for (int i = 0; i < lines.size(); i++) {
                    List<String> strlist  = new ArrayList<String>(Arrays.asList(lines.get(i).split(":")));
                    strlist.remove(0);strlist.remove(0);
                    if (strlist.contains(user)) {
                        filteredLines.add(lines.get(i));
                    }
                }
                return filteredLines;
            } catch (Exception e) {e.printStackTrace();}
            return new ArrayList<String>();
        }

        private List<String> auxGetPendByGroupPendID(String id, Path Path) {
            try {
                ArrayList<String> lines = new ArrayList<>(Files.readAllLines(Path, StandardCharsets.UTF_8));
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
    }
}