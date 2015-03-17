package client;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.*;
import javax.net.ssl.*;
import java.util.List;
import java.util.ArrayList;
import org.json.*;
import util.*;
import java.math.BigInteger;

import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    
    private static PrintWriter sockWriter;
    private static JSONWriter sockJS;
    private static BufferedReader sockReader;
    private static SSLSocket c;
    private static SecretKey key;
    private static Cipher encoder, decoder;
    
    public static void main(String[] args) {
        PrintStream out = System.out;
        SSLSocketFactory f = 
            (SSLSocketFactory) SSLSocketFactory.getDefault();

        sockReader = null;
        sockWriter = null;
      
        try {
            c = (SSLSocket) f.createSocket("localhost", 8888);

            c.startHandshake();

            printSocketInfo(c);

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            
            sockWriter = new PrintWriter(c.getOutputStream(), true);

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

    protected static String encryptPassword(String password) {
        byte[] encBytes;
        String encPass = password;

        if (password.charAt(password.length() - 1) == '\n')
            System.out.println("Found the newline!!!");

        try {
            encBytes = encoder.doFinal(password.getBytes("UTF-8"));
            encPass = bytesToHex(encBytes);
            System.out.println("Encrypted password with " + encPass.length() + " bytes.");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encPass;
    }

    protected static String decryptPassword(String encPass) {
        byte[] decBytes;
        String decPass = encPass;
        byte[] encBytes;
        byte[] properEncBytes;
        BigInteger b;

        try {
            System.out.println("Decoding " + encPass);
            b = new BigInteger(encPass, 16);
            encBytes = b.toByteArray();

            int extraLen = encBytes.length % 16;
            int properLen = encBytes.length - extraLen;
            properEncBytes = new byte[properLen];

            System.arraycopy((Object) encBytes, extraLen, (Object) properEncBytes, 0, properLen);
            
            decBytes = decoder.doFinal(properEncBytes);
            decPass = new String(decBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decPass;
    }

    /* Thanks StackOverflow! */
    protected static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    protected static Response responseFromString(String resp) {
        switch (resp) {
        case "SUCCESS": return Response.SUCCESS;
        case "WRONG_INPT": return Response.WRONG_INPT;
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
            
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return Response.FAIL;

        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            try {
                byte[] encPass, encKey, iv;
                SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");
                iv = new byte[16];
                srand.nextBytes(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                encKey = new byte[16];
                FileInputStream fin = new FileInputStream(System.getProperty("user.home") +
                                                          "/" + username + ".conf");
                fin.read(encKey);
            
                key = new SecretKeySpec(encKey, 0, 16, "AES");

                encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encoder.init(Cipher.ENCRYPT_MODE, key, ivSpec);

                decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
                decoder.init(Cipher.DECRYPT_MODE, key, ivSpec);

            } catch (Exception e) {
                System.out.println("Issues finding the key!");
                e.printStackTrace();
            }
        }
        
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

        if (err == Response.SUCCESS) {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                byte[] iv = new byte[16];
                IvParameterSpec ivSpec;
                SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");

                srand.nextBytes(iv);
                ivSpec = new IvParameterSpec(iv);
                
                keyGen.init(128);
                key = keyGen.generateKey();

                FileOutputStream fos = new FileOutputStream
                    (System.getProperty("user.home") + "/" + username +
                     ".conf");

                fos.write(key.getEncoded());
                fos.close();
                
                encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encoder.init(Cipher.ENCRYPT_MODE, key, ivSpec);

                decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
                decoder.init(Cipher.DECRYPT_MODE, key, ivSpec);

            } catch (Exception e) {
                System.out.println("Error in key generation and writeback!");
                e.printStackTrace();
            }
        }

        return err;
    }

    /* Add a set of credentials to an account.
     * pre: user is logged in
     * post: server adds that set of credentials to the account.
     */
    protected static Response addCreds(String service, String username, String password) {
        JSONObject respPacket = null;
        Response err;
        String encPass = encryptPassword(password);
        sockJS = new JSONWriter(sockWriter);
        

        sockJS.object()
            .key("command").value("ADD")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(encPass)
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

            return new Pair<Response, String>(err, username + "," + decryptPassword(password));
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
            .key("password").value(encryptPassword(password))
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
