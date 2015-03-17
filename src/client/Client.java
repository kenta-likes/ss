package client;

import java.io.*;
import java.net.*;

import javax.net.ssl.*;

import java.security.KeyStore;
import java.util.List;
import java.util.ArrayList;

import org.json.*;
import java.security.*;
import util.*;

public class Client {
    
    private static PrintWriter sockWriter;
    private static JSONWriter sockJS;
    private static BufferedReader sockReader;
    private static SSLSocket c;
    
    public static void main(String[] args) {
        PrintStream out = System.out;
        
        String ksName = System.getProperty("user.dir")+"/client/5430ts.jks"; //client side truststore
        char passphrase[] = "security".toCharArray();

        sockReader = null;
        sockWriter = null;
      
        try {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(ksName), passphrase);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keystore);

            SSLContext context = SSLContext.getInstance("TLS");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            context.init(null, trustManagers, new SecureRandom());
            SSLSocketFactory sf = context.getSocketFactory();
            SSLSocket c = (SSLSocket)sf.createSocket("localhost", 8888);
            c.startHandshake();
            printSocketInfo(c);

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            sockWriter = new PrintWriter(c.getOutputStream(), true);
            Shell.run();

            c.close();
        } catch (IOException e) {
            System.err.println(e.toString());
        } catch (Exception e1){//security stuff
            e1.printStackTrace();
        }
    }
    private static void printSocketInfo(SSLSocket s) {
        System.out.println("Socket class: "+s.getClass());
        System.out.println("   Remote address = "
                           +s.getInetAddress().toString());
        System.out.println("   Remote port = "+s.getPort());
        System.out.println("   Local socket address = "
                           +s.getLocalSocketAddress().toString());
        System.out.println("   Local address = "
                           +s.getLocalAddress().toString());
        System.out.println("   Local port = "+s.getLocalPort());
        System.out.println("   Need client authentication = "
                           +s.getNeedClientAuth());
        SSLSession ss = s.getSession();
        System.out.println("   Cipher suite = "+ss.getCipherSuite());
        System.out.println("   Protocol = "+ss.getProtocol());
    }

    protected static Response responseFromString(String resp) {
        switch (resp) {
        case "SUCCESS": return Response.SUCCESS;
        case "WRONG_INPT": return Response.WRONG_INPT;
        case "NO_SVC": return Response.NO_SVC;
        case "NAUTH": return Response.NAUTH;
        case "CRED_EXISTS": return Response.CRED_EXISTS;
        case "USER_EXISTS": return Response.USER_EXISTS;
        case "DUP_LOGIN": return Response.DUP_LOGIN;
        case "FAIL":
        default: return Response.FAIL;
        }
    }

    /* Login with the master username/password set. */
    protected static Response login(String username, char[] password) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);
        
        sockJS.object()
            .key("command").value("ATHN")
            .key("username").value(username)
            .key("password").value(new String(password))
            .endObject();
        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        	
        	//test:
        	//String s = sockReader.readLine();
        	//System.out.println("socket says:"+s);
        	//respPacket =  new JSONObject(s);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));
        return err;
    }

    /* Register a new account.
     * pre: user is not logged in
     * post: creates an account on the server with the associated account data.
     * It also authenticates that account immediately (user is logged in).
     */
    protected static Response register(String username, char[] password, String email) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);
        
        sockJS.object()
            .key("command").value("RGST")
            .key("username").value(username)
            .key("password").value(new String(password))
            .key("email").value(email)
            .endObject();

        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
            
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));

        return err;
    }

    /* Add a set of credentials to an account.
     * pre: user is logged in
     * post: server adds that set of credentials to the account.
     */
    protected static Response addCreds(String service, String username, String password) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("ADD")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(password)
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
            
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));

        return err;
    }

    /* Get credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: error code + the requested credentials.
     */
    protected static Pair<Response, String> requestCreds(String service) {
        JSONObject respPacket = null;
        Response err;
        String username, password;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("GET2")
            .key("service").value(service)
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (respPacket == null)
            return new Pair<Response, String>(Response.FAIL, null);

        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            username = respPacket.getString("username");
            password = respPacket.getString("password");

            return new Pair<Response, String>(err, username + "," + password);
        }

        return new Pair<Response, String>(err, null);
    }

    /* Get all credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: a list of all credentials associated with the user's account
     */
    protected static Pair<Response, List<String>> requestAllCreds() {
        JSONObject respPacket = null;
        JSONArray jsCreds = null;
        Response err;
        List<String> creds;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("GET1")
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return new Pair<Response, List<String>>(Response.FAIL, null);
        
        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            jsCreds = respPacket.getJSONObject("data").getJSONArray("credentials");

            creds = new ArrayList<String>(jsCreds.length());

            for (int i = 0; i < jsCreds.length(); i++) {
                creds.add(jsCreds.getString(i));
            }

            return new Pair<Response, List<String>>(err, creds);
        } else {
            return new Pair<Response, List<String>>(err, null);
        }
    }

    /* Deletes a set of credentials from the server.
     * pre: user is logged in, credentials exist on the server
     * post: that set of credentials no longer exists on the server
     */
    protected static Response deleteCreds(String service) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("REMV")
            .key("service").value(service)
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));
        return err;
    }

    /* Changes the username and password for a certain set of credentials.
     * pre: user is logged in, credentials exist on the server
     * post: the username or password for that set of credentials is changed
     */
    protected static Response changeCreds(String service, String username, String password) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("EDIT")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(password)
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));
        return err;
    }

    protected static Response changeMaster(char[] oldPassword, char[] newPassword) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("CHNG")
            .key("oldPassword").value(new String(oldPassword))
            .key("newPassword").value(new String(newPassword))
            .endObject();
        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));
        return err;
    }

    /* Logs out the user.
     * pre: user is logged in
     * post: user is no longer logged in
     */
    protected static Response logout() {
        Response err;
        JSONObject respPacket = null;
        
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("CLOSE")
            .endObject();

        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        err = responseFromString(respPacket.getString("response"));
        
        return err;
    }

    protected static Response unregister(char[] password) {
        Response err;
        JSONObject respPacket = null;
        
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("DEL")
            .key("password").value(new String(password))
            .endObject();

        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        err = responseFromString(respPacket.getString("response"));

        return err;
    }
}
