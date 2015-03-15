package client;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.util.List;
import java.util.ArrayList;
import org.json.*;

import server.ServerConnection.Response;

public class Client {
    
    private static JSONWriter sockWriter;
    private static BufferedReader sockReader;
    
    public static void main(String[] args) {
        PrintStream out = System.out;
        SSLSocketFactory f = 
            (SSLSocketFactory) SSLSocketFactory.getDefault();

        sockReader = null;
        sockWriter = null;
      
        try {
            SSLSocket c =
                (SSLSocket) f.createSocket("localhost", 8888);
            printSocketInfo(c);
            c.startHandshake();

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            
            sockWriter = new JSONWriter(new PrintWriter(c.getOutputStream(), true));

            Shell.run();

            c.close();
        } catch (IOException e) {
            System.err.println(e.toString());
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
        case "WRONG_PASS": return Response.WRONG_PASS;
        case "WRONG_USR": return Response.WRONG_USR;
        case "NO_SVC": return Response.NO_SVC;
        case "NAUTH": return Response.NAUTH;
        case "CRED_EXISTS": return Response.CRED_EXISTS;
        case "USER_EXISTS": return Response.USER_EXISTS;
        case "FAIL":
        default: return Response.FAIL;
        }
    }

    /* Login with the master username/password set. */
    protected static Response login(String username, char[] password) {
        JSONObject respPacket = null;
        Response err;

        sockWriter.object()
            .key("command").value("ATHN")
            .key("username").value(username)
            .key("password").value(new String(password))
            .endObject();

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

    /* Register a new account.
     * pre: user is not logged in
     * post: creates an account on the server with the associated account data.
     * It also authenticates that account immediately (user is logged in).
     */
    protected static Response register(String username, char[] password, String email) {
        return Response.SUCCESS;
    }

    /* Add a set of credentials to an account.
     * pre: user is logged in
     * post: server adds that set of credentials to the account.
     */
    protected static Response addCreds(String service, String username, String password) {
        JSONObject respPacket = null;
        Response err;

        sockWriter.object()
            .key("command").value("ADD")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(password)
            .endObject();
        
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

        sockWriter.object()
            .key("command").value("GET2")
            .key("service").value(service)
            .endObject();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (respPacket == null)
            return new Pair<Response, String>(Response.FAIL, null);

        err = responseFromString(respPacket.getString("response"));

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

        sockWriter.object()
            .key("command").value("GET1")
            .endObject();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return new Pair<Response, List<String>>(Response.FAIL, null);

        creds = new ArrayList<String>(jsCreds.length());
        
        err = responseFromString(respPacket.getString("response"));
        jsCreds = respPacket.getJSONObject("data").getJSONArray("credentials");

        for (int i = 0; i < creds.size(); i++) {
            creds.add(jsCreds.getString(i));
        }

        return new Pair<Response, List<String>>(err, creds);
    }

    /* Deletes a set of credentials from the server.
     * pre: user is logged in, credentials exist on the server
     * post: that set of credentials no longer exists on the server
     */
    protected static Response deleteCreds(String service) {
        JSONObject respPacket = null;
        Response err;

        sockWriter.object()
            .key("command").value("REMV")
            .key("service").value(service);

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

        sockWriter.object()
            .key("command").value("EDIT")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(password)
            .endObject();
        
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
        return Response.SUCCESS;
    }
}
