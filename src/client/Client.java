package client;

import java.io.*;
import javax.net.ssl.*;

import java.security.KeyStore;
import java.util.List;
import java.util.ArrayList;

import org.json.*;
import util.*;

import javax.xml.bind.DatatypeConverter;

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
    private static String username;
    
    public static void main(String[] args) {
        PrintStream out = System.out;
        
        String ksName = System.getProperty("user.dir")+"/client/5430ts.jks"; //client side truststore
        char passphrase[] = "security".toCharArray();

        sockReader = null;
        sockWriter = null;
        username = null;
      
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

    protected static String encryptPassword(String password) {
        byte[] encBytes;
        String encPass = password;

        try {
            
            encBytes = encoder.doFinal(password.getBytes("UTF-8"));
            /* Encode to a Base64 String representation. */
            encPass = DatatypeConverter.printBase64Binary(encBytes);
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encPass;
    }

    protected static String decryptPassword(String encPass) {
        byte[] decBytes, encBytes;
        String decPass = encPass;
        
        try {
            /* Decode bytes from Base64 String representation. */
            encBytes = DatatypeConverter.parseBase64Binary(encPass);
            
            decBytes = decoder.doFinal(encBytes);
            decPass = new String(decBytes, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decPass;
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

        if (err == Response.SUCCESS) {
            Client.username = username;
            try {
                byte[] encPass, encKey, iv;
                SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");
                IvParameterSpec ivSpec;
                FileInputStream fin = new FileInputStream(System.getProperty("user.home") +
                                                          "/" + username + ".conf");

                /* XXX Problem here.  Since we are determining a new IV *randomly* every
                 * time the user logs in, the decryption cipher will be initialized
                 * differently on each login.  This prevents us from being able to decrypt
                 * stored passwords once the user terminates the session.  So we need to
                 * either store the IV we used for the first encryption, or switch to ECB
                 * mode.
                 *
                 * I am going to store the IV we generate on registration in the same
                 * file as the key, but this is potentially a security issue.
                 */

                encKey = new byte[16];
                fin.read(encKey);

                /* Skip the newline character. */
                fin.skip(1);
                
                iv = new byte[16];
                fin.read(iv);

                ivSpec = new IvParameterSpec(iv);
                
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
            Client.username = username;
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
                fos.write((int) '\n');
                fos.write(iv);
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
     *
     * XXX TODO: ensure there are no commas (or delimit with non-printing characters!!!)
     */
    protected static Response addCreds(String service, String username, String password) {
        JSONObject respPacket = null;
        Response err;
        String encPass = encryptPassword(service + password);
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
        String username, password, decPass;
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

            decPass = decryptPassword(password);

            /* Make sure we are retrieving the password for the correct service! See details in design document
             * about the attack that would cause this.
             *
             * We are prepending the service name associated with a password before encrypting that password
             * and storing it on the server.
             */
            if (service.equals(decPass.substring(0, service.length() - 1))) {
                return new Pair<Response, String>(err, username + "," + decPass.substring(service.length()));
            } else {
                System.out.println("Error: detected password for incorrect service!  Please contact a system administrator.");
                return new Pair<Response, String>(Response.FAIL, null);
            }
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
            .key("password").value(encryptPassword(service + password))
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
            return responseFromString("IO Error getting response from server");
        }

        err = responseFromString(respPacket.getString("response"));
        username = null;
        
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
            return responseFromString("IO Error getting response from server");
        }

        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            File keyFile = new File(System.getProperty("user.home") + username + ".conf");
            keyFile.delete();
            username = null;
            err = logout();
        }

        return err;
    }
}
