import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignedObject;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Trokos {

    static final String delim = System.lineSeparator();

    public static void main(String[] args) {
        if (args.length != 5) {
            System.out.println("Please provide <serverIP:port> <truststore> <keystore> " +
            "<password-keystore> <userID> as arguments");
            System.exit(0);
        }

        String ip = args[0].split(":")[0];
        String port = args[0].split(":").length > 1 ? args[0].split(":")[1] : "45678";
        String trustStorePath = args[1];
        String keyStorePath = args[2];
        String pass_keyStore = args[3];
        String userID = args[4];

        System.setProperty("javax.net.ssl.trustStore", trustStorePath);

        try {
            // Load keystore, cert and key
            InputStream keyStoreData = new FileInputStream(keyStorePath);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(keyStoreData, pass_keyStore.toCharArray());
            String alias = ks.aliases().nextElement();
            final Certificate cert = ks.getCertificate(alias);
            final PrivateKey privK = (PrivateKey) ks.getKey(alias, pass_keyStore.toCharArray());
            final Signature sig = Signature.getInstance("SHA256withRSA");

            // Establish connection
            SocketFactory sf = SSLSocketFactory.getDefault();
            SSLSocket serverCon = (SSLSocket) sf.createSocket(ip, Integer.parseInt(port));
            Scanner scan = new Scanner(System.in);
            final ObjectOutputStream serverOut = new ObjectOutputStream(serverCon.getOutputStream());
            final ObjectInputStream serverIn = new ObjectInputStream(serverCon.getInputStream());
            Runtime.getRuntime().addShutdownHook(new Thread(() -> { 
                try {serverCon.close();scan.close();} catch (IOException e) {e.printStackTrace();}
            }));

            // Attempt authentication with server
            System.out.println("Attempting to authenticate with server...");
            serverOut.writeObject(userID);

            Long nonce = (Long) serverIn.readObject();
            Boolean userExists = (Boolean) serverIn.readObject();

            SignedObject signedNonce = new SignedObject(nonce, privK, sig);
            if (!userExists) {
                serverOut.writeObject(cert);
            } 
            serverOut.writeObject(signedNonce);

            // Server response
            String response = (String) serverIn.readObject();
            String[] s = response.split(":");
            if (s[0].equals("FAILURE")) {
                System.out.println(s[1]);
                System.exit(-1);
            } else {
                System.out.println(s[1]);
            }


            // Main commands loop
            showCommands();
            while(true) {
                System.out.print("> ");
                String input = scan.nextLine();
                String[] command = input.split(" ");

                switch (command[0]) {
                    case "o":
                    case "obtainQRcode":
                        serverOut.writeObject(command);
                        String r = (String)serverIn.readObject();
                        if (r.equals("ERROR")) {
                            System.out.println(delim+(String)serverIn.readObject());
                        } else {
                            String imgstr = (String)serverIn.readObject();
                            String code = (String)serverIn.readObject();
                            byte[] bytes = Base64.getDecoder().decode(imgstr);
                            Files.write(Paths.get(code+".png"), bytes);
                            System.out.println(delim+"Success! QRcode image created in this folder"+delim);
                        }
                        break;
                    case "m":
                    case "makepayment":
                        serverOut.writeObject(command);
                        String[] t_array = Arrays.copyOfRange(command, 1, command.length);
                        // String transaction = "receiver:amount:sender"
                        String transaction = String.join(":", t_array) + ":" + userID;
                        SignedObject signed_t = new SignedObject(transaction, privK, sig);

                        serverOut.writeObject(signed_t);
                        System.out.println(delim+(String)serverIn.readObject()+delim);
                        break;
                    case "p":
                    case "payrequest":
                        String[] getreq = {"getrequest", command[1]};
                        serverOut.writeObject(getreq);
                        String ansr = (String) serverIn.readObject();
                        String[] splt = ansr.split(":");
                        if (splt[0].equals("ERROR")) {
                            System.out.println(delim+splt[1]+delim);
                        } else {
                            serverOut.writeObject(command);
                            transaction = ansr+":"+userID;
                            signed_t = new SignedObject(transaction, privK, sig);

                            serverOut.writeObject(signed_t);
                            System.out.println(delim+(String)serverIn.readObject()+delim);
                        }
                        break;
                    case "c":
                    case "confirmQRcode":
                        String[] getqrreq = {"getrequestQR", command[1]};
                        serverOut.writeObject(getqrreq);
                        String asr = (String) serverIn.readObject();
                        String[] sp = asr.split(":");
                        if (sp[0].equals("ERROR")) {
                            System.out.println(delim+sp[1]+delim);
                        } else {
                            serverOut.writeObject(command);
                            transaction = asr+":"+userID;
                            signed_t = new SignedObject(transaction, privK, sig);

                            serverOut.writeObject(signed_t);
                            System.out.println(delim+(String)serverIn.readObject()+delim);
                        }
                        break;
                    default:
                        serverOut.writeObject(command);
                        System.out.println(delim+(String)serverIn.readObject()+delim);
                }
            }

        } catch (Exception e) {
            if (e instanceof SocketException && e.getMessage().contains("Connection reset")) {
                System.out.println("Lost connection to server!");
                System.exit(0);
            }
            if (e instanceof ConnectException) {
                System.out.println("Can't reach server!");
                System.exit(0);
            }
            if (e instanceof NoSuchElementException) {}
            else {e.printStackTrace();}
        }
    }

    static public void showCommands() {
        System.out.println(delim+"Comandos disponiveis:"+delim);
        System.out.println("   -balance");
        System.out.println("      obtem valor atual do saldo da sua conta.");
        System.out.println("   -makepayment <userID> <amount>");
        System.out.println("      transferir o valor amount para a conta de userID.");
        System.out.println("   -requestpayment <userID> <amount>");
        System.out.println("      envia um pedido de pagamento ao");
        System.out.println("      utilizador userID, de valor amount");
        System.out.println("   -viewrequests");
        System.out.println("      obtem do servidor a sua lista de pedidos");
        System.out.println("      de pagamentos pendentes");
        System.out.println("   -payrequest <reqID>");
        System.out.println("      autoriza o pagamento do pedido com");
        System.out.println("      identificador reqID.");
        System.out.println("   -obtainQRcode <amount>");
        System.out.println("      cria um pedido de pagamento no servidor");
        System.out.println("      e recebe a imagem do QRcode.");
        System.out.println("   -confirmQRcode <QRcode>");
        System.out.println("      confirma e autoriza o pagamento");
        System.out.println("      identificado por QR code.");
        System.out.println("   -newgroup <groupID>");
        System.out.println("      cria um grupo para pagamentos partilhados");
        System.out.println("   -addu <userID> <groupID>");
        System.out.println("      adiciona o utilizador userID como");
        System.out.println("      membro do grupo indicado.");
        System.out.println("   -groups");
        System.out.println("      mostra uma lista dos grupos de que o");
        System.out.println("      cliente eh dono, e uma lista dos");
        System.out.println("      grupos a que pertence.");
        System.out.println("   -dividepayment <groupID> <amount>");
        System.out.println("      cria um pedido de pagamento de grupo, cujo valor");
        System.out.println("      total amount deve ser dividido pelos");
        System.out.println("      membros do grupo groupID");
        System.out.println("   -statuspayments <groupID>");
        System.out.println("      mostra o estado de cada pedido de pagamento de");
        System.out.println("      grupo, ou seja, que membros do grupo ainda");
        System.out.println("      nao pagaram esse pedido");
        System.out.println("   -history <groupID>");
        System.out.println("      mostra o historico dos pagamentos do");
        System.out.println("      grupo groupID ja concluidos.");
        System.out.println();
    }
}
