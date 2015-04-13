package client;

import java.io.*;

import javax.net.ssl.*;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.Charset;
import java.nio.ByteBuffer;

import org.json.*;

import util.*;

import javax.xml.bind.DatatypeConverter;

import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private static final String HOSTNAME = "localhost";
    
    private static PrintWriter sockWriter;
    private static JSONWriter sockJS;
    private static BufferedReader sockReader;
    private static SecretKey key;
    private static Cipher encoder, decoder;
    private static String username;
    
    public static void main(String[] args) {
        
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
            SSLSocket c = (SSLSocket)sf.createSocket(HOSTNAME, 8888);
            c.startHandshake();

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
        byte[] encBytes, decBytes;
        String encPass = password;

        try {
            Charset charSet = Charset.forName("UTF-8");
            decBytes = charSet.encode(password).array();
            
            encBytes = encoder.doFinal(decBytes);
            
            /* Encode to a Base64 String representation. */
            encPass = DatatypeConverter.printBase64Binary(encBytes);
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encPass;
    }

    protected static char[] decryptPassword(String encPass) {
        byte[] decBytes, encBytes;
        char[] decPass = null;
        
        try {
            /* Decode bytes from Base64 String representation. */
            encBytes = DatatypeConverter.parseBase64Binary(encPass);
            
            decBytes = decoder.doFinal(encBytes);

            Charset charSet = Charset.forName("UTF-8");
            /* Return a char array so we can zero it out after printing it. */
            decPass = charSet.decode(ByteBuffer.wrap(decBytes)).array();
            
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
        case "BAD_FORMAT": return Response.BAD_FORMAT;
        case "FAIL":
        default: return Response.FAIL;
        }
    }
    
    public static byte[] charToBytes(char in[])
    {
    	int i;
    	byte ret[] = new byte[in.length];
    	for (i = 0; i < in.length; i++)
    	{
    		ret[i] = (byte) in[i];
    	}
    	return ret;
    }

    /* Login with the master username/password set. */
    protected static Response login(String username, char[] password) {
        JSONObject respPacket = null;
        Response err;
        byte hashedPassword[];
        byte passwordBytes[] = charToBytes(password);
        try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(passwordBytes);
			hashedPassword = digest.digest();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
			return Response.FAIL;
		}
        
        sockJS = new JSONWriter(sockWriter);
        
        sockJS.object()
            .key("command").value("ATHN")
            .key("username").value(username)
            .key("password").value(hashedPassword)
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
            return Response.FAIL;
        }
        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            Client.username = username;
            try {
                byte[] salt, iv;
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

                salt = new byte[16];
                fin.read(salt);

                /* Skip the newline character. */
                fin.skip(1);
                
                iv = new byte[16];
                fin.read(iv);
                fin.close();
                ivSpec = new IvParameterSpec(iv);
                
                SecretKeyFactory keyFact=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
                SecretKey tmp = keyFact.generateSecret(spec);
                key = new SecretKeySpec(tmp.getEncoded(), "AES");
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
        byte hashedPassword[];
        try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(password.toString().getBytes());
			hashedPassword = digest.digest();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
			return Response.FAIL;
		}
        sockJS.object()
            .key("command").value("RGST")
            .key("username").value(username)
            .key("password").value(new String(hashedPassword))
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
                byte[] iv = new byte[16];
                byte[] salt = new byte[16];
                IvParameterSpec ivSpec;
                SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");

                srand.nextBytes(iv);
                ivSpec = new IvParameterSpec(iv);
                
                srand.nextBytes(salt);

                FileOutputStream fos = new FileOutputStream
                    (System.getProperty("user.home") + "/" + username +
                     ".conf");

                fos.write(salt);
                fos.write((int) '\n');
                fos.write(iv);
                fos.close();

                SecretKeyFactory keyFact=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
                SecretKey tmp = keyFact.generateSecret(spec);
                key = new SecretKeySpec(tmp.getEncoded(), "AES");
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
        
        byte code[];
        try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(service.getBytes());
			mac.update(username.getBytes());
			mac.update(password.getBytes());
			System.out.println(service + ", " + username + ", " + password);
			code = mac.doFinal();
		} catch (Exception e1) {
			e1.printStackTrace();
			return Response.FAIL;
		}
        sockJS.object()
            .key("command").value("ADD")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(encPass)
            .key("mac").value(new String(code))
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        
        try {
            respPacket = new JSONObject(sockReader.readLine());
            
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null) {
            return Response.FAIL;
        }

        err = responseFromString(respPacket.getString("response"));

        return err;
    }

    /* Get credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: error code + the requested credentials.
     */
    protected static Pair<Response, Pair<String, char[]>> requestCreds(String service) {
        JSONObject respPacket = null;
        Response err;
        String username, password, mac, computedMac;
        char[] decPass;
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
            return new Pair<Response, Pair<String, char[]>>(Response.FAIL, null);

        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            boolean correctService = true;
            char[] justPass;
            username = respPacket.getString("username");
            password = respPacket.getString("password");
            mac = respPacket.getString("mac");
            byte code[];
            decPass = decryptPassword(password);
            justPass = new char[decPass.length - service.length()];



            /* Make sure we are retrieving the password for the correct service! See details in design document
             * about the attack that would cause this.
             *
             * We are prepending the service name associated with a password before encrypting that password
             * and storing it on the server.
             */

            /* Substring for char array and string comparison */
            for (int i = 0; i < service.length(); i++) {
                correctService &= (decPass[i] == service.charAt(i));
            }

            if (correctService) {
                
                for (int i = service.length(); i < decPass.length; i++)
                    justPass[i - service.length()] = decPass[i];

                for (int i = 0; i < decPass.length; i++)
                    decPass[i] = (char) 0;
                
                try {
        			Mac mac_compute = Mac.getInstance("HmacSHA256");
        			mac_compute.init(key);
        			mac_compute.update(service.getBytes());
        			mac_compute.update(username.getBytes());
        			mac_compute.update(charToBytes(justPass));
        			System.out.println(service + ", " + username + ", " + new String(justPass));
        			code = mac_compute.doFinal();
        			computedMac = new String(code);
        			if (!computedMac.equals(mac))
        			{
        				return new Pair<Response, Pair<String, char[]>>(Response.MAC, null);
        			}
        		} catch (Exception e1) {
        			e1.printStackTrace();
        			return new Pair<Response, Pair<String, char[]>>(Response.FAIL, null);
        		}
                
                return new Pair<Response, Pair<String, char[]>>(err, new Pair<String, char[]>(username, justPass));
                
            } else {
                for (int i = 0; i < decPass.length; i++)
                    decPass[i] = (char) 0;

                System.out.println("Error: detected password for incorrect service!  Please contact a system administrator.");
                return new Pair<Response, Pair<String, char[]>>(Response.FAIL, null);
            }
        }

        return new Pair<Response, Pair<String, char[]>>(err, null);
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
