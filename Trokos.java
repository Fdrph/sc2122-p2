import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Scanner;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Trokos {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Please provide <serverIP:port> <userID> <password> as arguments");
        }

        String ip = args[0].split(":")[0];
        String port = args[0].split(":").length > 1 ? args[0].split(":")[1] : "45678";
        String trustStore = args[1];
        String keyStore = args[2];
        String pass_keyStore = args[3];
        String userID = args[4];

        System.setProperty("javax.net.ssl.trustStore", trustStore);

        try {
            SocketFactory sf = SSLSocketFactory.getDefault();
            SSLSocket serverCon = (SSLSocket) sf.createSocket(ip, Integer.parseInt(port));
            Scanner scan = new Scanner(System.in);
            ObjectOutputStream outStream = new ObjectOutputStream(serverCon.getOutputStream());
            ObjectInputStream inStream = new ObjectInputStream(serverCon.getInputStream());
            Runtime.getRuntime().addShutdownHook(new Thread(() -> { 
                try {serverCon.close();scan.close();} catch (IOException e) {e.printStackTrace();}
            }));

            // Attempt authentication with server
            System.out.println("Attempting to authenticate with server...");
            outStream.writeObject(userID);
            outStream.writeObject(pass_keyStore);

            // Response
            String response = (String)inStream.readObject();
            if (response.split(":")[0].equals("Failure")) {
                System.out.println("Wrong Password!");
                serverCon.close();
                System.exit(0);
            } else {
                System.out.println(response);
            }

            // Main commands loop
            showCommands();
            while(true) {
                System.out.print("> ");
                String input = scan.nextLine();
                String[] command = input.split(" ");

                if (command[0].equals("o") || command[0].equals("obtainQRcode")) {
                    outStream.writeObject(command);
                    String r = (String)inStream.readObject();
                    if (r.equals("ERROR")) {
                        System.out.println();
                        System.out.println((String)inStream.readObject());
                    } else {
                        String imgstr = (String)inStream.readObject();
                        String code = (String)inStream.readObject();
                        byte[] bytes = Base64.getDecoder().decode(imgstr);
                        Files.write(Paths.get(code+".png"), bytes);
                        System.out.println();
                        System.out.println("Success! QRcode image created in this folder");
                    }
                } else {
                    outStream.writeObject(command);
                    System.out.println();
                    System.out.println((String)inStream.readObject());
                }
                System.out.println();
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
        System.out.println(System.lineSeparator()+"Comandos disponíveis:"+System.lineSeparator());
        System.out.println("   -balance");
        System.out.println("      obtém valor atual do saldo da sua conta.");
        System.out.println("   -makepayment <userID> <amount>");
        System.out.println("      transferir o valor amount para a conta de userID.");
        System.out.println("   -requestpayment <userID> <amount>");
        System.out.println("      envia um pedido de pagamento ao");
        System.out.println("      utilizador userID, de valor amount");
        System.out.println("   -viewrequests");
        System.out.println("      obtém do servidor a sua lista de pedidos");
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
        System.out.println("      cliente é dono, e uma lista dos");
        System.out.println("      grupos a que pertence.");
        System.out.println("   -addu <userID> <groupID>");
        System.out.println("      adiciona o utilizador userID como");
        System.out.println("      membro do grupo indicado.");
        System.out.println("   -dividepayment <groupID> <amount>");
        System.out.println("      cria um pedido de pagamento de grupo, cujo valor");
        System.out.println("      total amount deve ser dividido pelos");
        System.out.println("      membros do grupo groupID");
        System.out.println("   -statuspayments <groupID>");
        System.out.println("      mostra o estado de cada pedido de pagamento de");
        System.out.println("      grupo, ou seja, que membros do grupo ainda");
        System.out.println("      nao pagaram esse pedido");
        System.out.println("   -history <groupID>");
        System.out.println("      mostra o histórico dos pagamentos do");
        System.out.println("      grupo groupID já concluídos.");
        System.out.println();
    }
}
