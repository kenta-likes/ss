package logging;

import java.io.*;
import javax.net.ssl.*;
import org.json.*;
import util.*;
import java.io.Console;
import java.security.SecureRandom;
import java.security.KeyStore;

public class LogClient {

    private static PrintWriter sockWriter;
    private static JSONWriter sockJS;
    private static BufferedReader sockReader;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("error: did not receive hostname argument");
            return;
        }

        String ksName = "client/5430ts.jks"; //client side truststore
        char passphrase[] = "security".toCharArray();

        String hostname = args[0];

        sockReader = null;
        sockWriter = null;
        SSLSocket c = null;
      
        try {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(ksName), passphrase);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keystore);

            SSLContext context = SSLContext.getInstance("TLSv1.2");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            context.init(null, trustManagers, new SecureRandom());
            SSLSocketFactory sf = context.getSocketFactory();
            c = (SSLSocket)sf.createSocket(hostname, Consts.LOGSERVER_PORT);
            c.setEnabledCipherSuites(Consts.ACCEPTED_SUITES);
            c.startHandshake();

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            sockWriter = new PrintWriter(c.getOutputStream(), true);

        } catch (IOException e) {
            System.err.println(e.toString());
        } catch (Exception e1){//security stuff
            e1.printStackTrace();
        }

        Console con = System.console();

        if (con == null) {
            try {
                c.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }

        char[] password = con.readPassword("Password: ");
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("AUTH")
            .key("password").value(new String(password))
            .endObject();

        sockWriter.println();
        sockWriter.flush();

        try {
            JSONObject resp = new JSONObject(sockReader.readLine());
            if (!resp.getString("response").equals("SUCCESS")) {
                System.out.println("Incorrect password.");
                c.close();
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        while (true) {
            String command = con.readLine("PassHerd-LogClient-0.9b$ ");
            String[] splitCommand = command.split(" ");

            sockJS = new JSONWriter(sockWriter);

            switch (splitCommand[0]) {
            case "get":
                if (splitCommand.length == 2) {
                    try {
                        sockJS.object()
                            .key("command").value("GET")
                            .key("lines").value(splitCommand[1])
                            .endObject();

                        sockWriter.println();
                        sockWriter.flush();

                        JSONObject resp = new JSONObject(sockReader.readLine());
                        if (!resp.getString("response").equals("SUCCESS"))
                            System.out.println("Error: unknown failure.");
                        else {
                            System.out.println(resp.getString("log"));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Error: unknown failure.");
                    }
                } else {
                    System.out.println("Error: Invalid command.");
                }
            
                break;
            
            case "exit":
                try {
                    sockJS.object()
                        .key("command").value("CLOSE")
                        .endObject();
                    sockWriter.println();
                    sockWriter.flush();
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    return;
                }
            }
        }
    }
}
