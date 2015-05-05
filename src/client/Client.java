package client;

import java.io.*;

import javax.net.ssl.*;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.Charset;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Arrays;

import org.json.*;

import util.*;

import javax.xml.bind.DatatypeConverter;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.NoSuchProviderException;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {

    //    private static final String HOSTNAME = "localhost";
    
    private static PrintWriter sockWriter;
    private static JSONWriter sockJS;
    private static BufferedReader sockReader;
    private static SecretKey key;
    private static Cipher encoder, decoder;
    private static String username;
    
    public static void main(String[] args) {
        
        String ksName = System.getProperty("user.dir")+"/client/5430ts.jks"; //client side truststore
        char passphrase[] = "security".toCharArray();

        if (args.length != 1) {
            System.out.println("Usage: java -jar Client.jar <server hostname>");
            return;
        }

        String hostname = args[0];

        sockReader = null;
        sockWriter = null;
        username = null;
      
        try {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(ksName), passphrase);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keystore);

            SSLContext context = SSLContext.getInstance("TLSv1.2");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            context.init(null, trustManagers, new SecureRandom());
            SSLSocketFactory sf = context.getSocketFactory();
            SSLSocket c = (SSLSocket)sf.createSocket(hostname, 8888);
            c.setEnabledCipherSuites(Consts.ACCEPTED_SUITES);
            c.startHandshake();

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            sockWriter = new PrintWriter(c.getOutputStream(), true);

            Runtime.getRuntime().addShutdownHook(new Thread() {
                    public void run() {
                        try {
                            new JSONWriter(sockWriter).object().key("command").value("CLOSE")
                                .endObject();

                            sockWriter.println();
                            sockWriter.flush();

                            c.close();
                        } catch (IOException e) {
                            //failed
                        }
                    }
                });
            
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
    
    // PBE
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
        case "USER_DNE": return Response.USER_DNE;
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
            .key("command").value("LGIN")
            .key("username").value(username)
            .key("password").value(new String(hashedPassword))
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
        return err;
    }
    
    /* Login with the master username/password set. */
    protected static Response auth(String username, char[] password, String code) {
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
            .key("password").value(new String(hashedPassword))
            .key("code").value(code)
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
    protected static Response register(String username, char[] password, String phone, String carrier) {
        JSONObject respPacket = null;
        Response err;
        sockJS = new JSONWriter(sockWriter);
        byte hashedPassword[];
        byte passwordbytes[] = charToBytes(password);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(passwordbytes);
            hashedPassword = digest.digest();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
            return Response.FAIL;
        }
        sockJS.object()
            .key("command").value("RGST")
            .key("username").value(username)
            .key("password").value(new String(hashedPassword))
            .key("phone").value(phone)
            .key("carrier").value(carrier)
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
        String encPass = encryptPassword(password);
        sockJS = new JSONWriter(sockWriter);
        /*        SecretKey macKey = new SecretKeySpec(key.getEncoded(), "HmacSHA256");
                  String message = service + username + password;
        
                  byte code[];
        
                  try {
                  Mac mac = Mac.getInstance("HmacSHA256");
                  mac.init(macKey);
            
                  code = mac.doFinal("This is a very long string...hopefully it works.".getBytes());
                  } catch (Exception e1) {
                  e1.printStackTrace();
                  return Response.FAIL;
                  }*/
        
        sockJS.object()
            .key("command").value("ADD")
            .key("service").value(service)
            .key("username").value(username)
            .key("password").value(encPass)
            //            .key("mac").value(DatatypeConverter.printBase64Binary(code))
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

    protected static Response getTransactions(){
      Response err;
      JSONObject respPacket = null;
      try{
        sockJS = new JSONWriter(sockWriter);
        sockJS.object()
            .key("command").value("GET_TRANS")
            //            .key("mac").value(DatatypeConverter.printBase64Binary(code))
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        System.out.println("client sent get transactions command");
        respPacket = new JSONObject(sockReader.readLine());
      } catch (Exception e) {
          e.printStackTrace();
          return Response.FAIL; //failed
      }
      if (respPacket == null) {
        return Response.FAIL;
      }
      err = responseFromString(respPacket.getString("response"));
      if(!err.equals(Response.SUCCESS)){
        return err;
      }
      System.out.println("client received list, now iterating over it");
      //encrypt the public keys, send back
      JSONArray pub_keys = respPacket.getJSONArray("pub_keys");
      ArrayList<String> pub_keys_encrypted = new ArrayList<String>();
      for (int i = 0; i < pub_keys.length(); i++) {
          String pubkey = pub_keys.getString(i);
          // Encrypt pubkey using PBE
          pub_keys_encrypted.add(encryptPassword(pubkey));
      }
      sockJS = new JSONWriter(sockWriter);
      sockJS.object().key("command").value("SET_PUB")
                  .key("pub_keys").value(new JSONArray(pub_keys_encrypted.toArray()))
                  .endObject();
      sockWriter.println();
      sockWriter.flush();
      System.out.println("client sent re-encrypted stuff");
      // Receive results from the server 
      try {
        respPacket = new JSONObject(sockReader.readLine());
        if (respPacket == null){
          return Response.FAIL;
        }
        err = responseFromString(respPacket.getString("response"));
        return err;
      } catch (Exception e){
        e.printStackTrace();
        return Response.FAIL;
      }
      
    }

    /*Used for generating key pair using PBE and the service name*/
    protected static KeyPair getKeyPair(String service, char[] pass){
        try {
          MessageDigest md = MessageDigest.getInstance("SHA-256");
          char combined[] = new char[pass.length + service.toCharArray().length];
          System.arraycopy(pass, 0, combined, 0, pass.length);
          System.arraycopy(service.toCharArray(), 0, combined, pass.length, service.toCharArray().length);

          CharBuffer charBuffer = CharBuffer.wrap(combined);
          ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
          byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                                              byteBuffer.position(), byteBuffer.limit());
          md.update(bytes);
          byte[] digest = md.digest();

          KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
          SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
          rng.setSeed(digest); //use the password/service name hashed as seed
          keyGen.initialize(512, rng);
          return keyGen.genKeyPair();
        } catch (Exception e) {
          e.printStackTrace();
          return null;
        }
    }

    /*generates cipher text from plaintext using a keypair*/
    protected static byte[] encryptWithKeyPair(KeyPair shared_keypair, char[] msg){
        try {
        final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, shared_keypair.getPrivate());
        /*get the password from the creds retrieved*/
        CharBuffer charBuffer = CharBuffer.wrap(msg);
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                                            byteBuffer.position(), byteBuffer.limit());
        return cipher.doFinal(bytes);
        } catch (Exception e){
          e.printStackTrace();
          return null;
        }
    }

    /*generates plaintext from ciphertext using a keypair*/
    protected static char[] decryptWithKeyPair(KeyPair shared_keypair, byte[] c_msg){
        try {
        final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, shared_keypair.getPublic());
        byte[] bytes = cipher.doFinal(c_msg);
        char[] msg = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            msg[i] = (char) (bytes[i] & 0xff);
        }
        return msg;
        } catch (Exception e){
          e.printStackTrace();
          return null;
        }
    }

    /*share creds with another user
      assumes user is already authenticated*/
    protected static Response shareNewCreds(String service, String user_shared, char[] pass) {
      Response err;
      JSONObject respPacket = null;
      Pair<Response, Pair<String, char[]>> creds = requestCreds(service);
      if (creds.first() != Response.SUCCESS){
        return creds.first(); //send failed response
      }
      try {
        KeyPair shared_keypair = getKeyPair(service,pass);
        if (shared_keypair == null){
          return Response.FAIL;
        }
        byte[] publicKey = shared_keypair.getPublic().getEncoded();

        sockJS = new JSONWriter(sockWriter);
        sockJS.object()
            .key("command").value("SHARE")
            .key("user").value(user_shared)
            .key("service").value(service)
            .key("service_user").value(DatatypeConverter.printBase64Binary(encryptWithKeyPair(shared_keypair, creds.second().first().toCharArray())))
            .key("service_pass").value(DatatypeConverter.printBase64Binary(encryptWithKeyPair(shared_keypair, creds.second().second())))
            .key("public_key").value(DatatypeConverter.printBase64Binary(publicKey))
            //            .key("mac").value(DatatypeConverter.printBase64Binary(code))
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        respPacket = new JSONObject(sockReader.readLine());
      } catch (Exception e) {
          e.printStackTrace();
          Arrays.fill(pass, '\0');
          return Response.FAIL; //failed
      }
      if (respPacket == null) {
        Arrays.fill(pass, '\0');
        return Response.FAIL;
      }
      err = responseFromString(respPacket.getString("response"));
      Arrays.fill(pass, '\0');
      return err;
    }

    /*Sends command to revoke access for a user who had been shared a credential*/
    protected static Response unshareCreds(String revoked_user, String service){
      JSONObject respPacket = null;
      Response err;
      try {
        sockJS = new JSONWriter(sockWriter);
        sockJS.object()
            .key("command").value("REVOKE")
            .key("revoked_user").value(revoked_user)
            .key("revoked_service").value(service)
            //            .key("mac").value(DatatypeConverter.printBase64Binary(code))
            .endObject();
        sockWriter.println();
        sockWriter.flush();
        respPacket = new JSONObject(sockReader.readLine());
      } catch (Exception e) {
          e.printStackTrace();
          return Response.FAIL; //failed
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
        String username, password, computedMac;
        char[] decPass;
        byte[] mac;
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

            return new Pair<Response, Pair<String, char[]>>(err, new Pair<String, char[]>
                                                            (username, decryptPassword(password)));
                                                            
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

    protected static Pair<Response, List<Pair<String, String>>> requestSharedCreds() {
        JSONObject respPacket = null;
        JSONArray jsCreds = null;
        Response err;
        List<Pair<String, String>> creds;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("GETSHARED1")
            .endObject();
        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return new Pair<Response, List<Pair<String, String>>>(Response.FAIL, null);

        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            jsCreds = respPacket.getJSONObject("data").getJSONArray("credentials");
            creds = new ArrayList<Pair<String, String>>();

            try {
                for (int i = 0; i < jsCreds.length(); i++) {
                    Pair<String, String> sharedService;
                    String owner, service;
                    JSONObject o = new JSONObject(jsCreds.getString(i));

                    owner = o.getString("owner");
                    service = o.getString("service");

                    sharedService = new Pair<String, String>(owner, service);

                    creds.add(sharedService);
                }
            } catch (Exception e) {
                e.printStackTrace();
                return new Pair<Response, List<Pair<String, String>>>(Response.FAIL, null);
            }
        }

        return new Pair<Response, List<Pair<String, String>>>(Response.FAIL, null);
    }

    protected static Pair<Response, List<Pair<String, List<String>>>>
        listShares() {

        JSONObject respPacket = null;
        Response err;
        List<Pair<String, List<String>>> shares;

        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("ACL")
            .endObject();

        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (Exception e) {
            e.printStackTrace();
            return new Pair<Response, List<Pair<String, List<String>>>>(Response.FAIL, null);
        }

        if (respPacket == null)
            return new Pair<Response, List<Pair<String, List<String>>>>(Response.FAIL, null);

        err = responseFromString(respPacket.getString("response"));
        
        if (err == Response.SUCCESS) {
            JSONArray jsShares = respPacket.getJSONObject("shares").getJSONArray("creds");
            shares = new ArrayList<Pair<String, List<String>>>();

            for (int i = 0; i < jsShares.length(); i++) {
                JSONObject cred = new JSONObject(jsShares.get(i));
                String service;
                List<String> users = new ArrayList<String>();
                JSONArray jsUsers = cred.getJSONArray("users");

                service = cred.getString("service");

                for (int j = 0; j < jsUsers.length(); j++) {
                    users.add(jsUsers.getString(j));
                }

                shares.add(new Pair<String, List<String>>(service, users));
            }

            return new Pair<Response, List<Pair<String, List<String>>>>(err, shares);
        }

        return new Pair<Response, List<Pair<String, List<String>>>>(err, null);
    }

    protected static Response unshare(String service, String username) {
        JSONObject respPacket = null;

        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("REVOKE")
            .key("revoked_service").value(service)
            .key("revoked_user").value(username)
            .endObject();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (Exception e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        if (respPacket == null)
            return Response.FAIL;

        return responseFromString(respPacket.getString("response"));
    }
    
    

    protected static Pair<Response, Pair<String, String>>
        requestOneSharedCred(String service, String owner) {

        JSONObject respPacket = null;
        Response err;
        String username, password, encPublicKey;
        char[] decPass;
        sockJS = new JSONWriter(sockWriter);

        sockJS.object()
            .key("command").value("GETSHARED2")
            .key("service").value(service)
            .key("owner").value(owner)
            .endObject();
        sockWriter.println();
        sockWriter.flush();

        try {
            respPacket = new JSONObject(sockReader.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (respPacket == null)
            return new Pair<Response, Pair<String, String>>(Response.FAIL, null);

        err = responseFromString(respPacket.getString("response"));

        if (err == Response.SUCCESS) {
            encPublicKey = respPacket.getString("public_key");
            username = respPacket.getString("username");
            password = respPacket.getString("password");

            try {
                byte[] pubKeyBytes = DatatypeConverter.parseBase64Binary(encPublicKey);
                X509EncodedKeySpec k = new X509EncodedKeySpec(pubKeyBytes);
            
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(k);
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, publicKey);
            
                username = new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(username)));
                password = new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(password)));

                return new Pair<Response, Pair<String, String>>(err, new Pair<String, String>(username, password));
            } catch (Exception e) {
                e.printStackTrace();
                return new Pair<Response, Pair<String, String>>(Response.FAIL, null);
            }
        }

        return new Pair<Response, Pair<String, String>>(err, null);
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
        MessageDigest digest;
        sockJS = new JSONWriter(sockWriter);
        byte[] hashedOldPassword, oldPasswordBytes, hashedNewPassword, newPasswordBytes;

        oldPasswordBytes = charToBytes(oldPassword);
        newPasswordBytes = charToBytes(newPassword);

        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest.update(oldPasswordBytes);
            hashedOldPassword = digest.digest();

            digest.reset();

            digest.update(newPasswordBytes);
            hashedNewPassword = digest.digest();
            
        } catch (Exception e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        sockJS.object()
            .key("command").value("CHNG")
            .key("oldPassword").value(new String(hashedOldPassword))
            .key("newPassword").value(new String(hashedNewPassword))
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
        
        redoCredentialEncryption(newPassword);
        err = responseFromString(respPacket.getString("response"));
        System.out.println(err);
        return err;
    }

    /*
     * After changing the master password, need to get all credentials from the server,
     * decrypt them, re-encrypt with the new password, and re-store them on the server
     */
    private static void redoCredentialEncryption(char[] newPassword) {
        // TODO Auto-generated method stub
        Pair<Response, List<String>> credNames = requestAllCreds();
        List<Pair<String,char[]>> creds = new LinkedList<Pair<String,char[]>>();
        Pair<Response, Pair<String, char[]>> response;
        int i;
        for (i = 0; i < credNames.second().size(); i++)
            {
                response = requestCreds(credNames.second().get(i));
                creds.add(new Pair<String, char[]>(response.second().first(), response.second().second()));
            }
        byte[] salt, iv;
        IvParameterSpec ivSpec;
        FileInputStream fin;

        try {
            fin = new FileInputStream(System.getProperty("user.home") +
                                      "/" + username + ".conf");
            salt = new byte[16];
            fin.read(salt);
	
            /* Skip the newline character. */
            fin.skip(1);
	        
            iv = new byte[16];
            fin.read(iv);
            fin.close();
            ivSpec = new IvParameterSpec(iv);
	        
            SecretKeyFactory keyFact=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(newPassword, salt, 65536, 256);
            SecretKey tmp = keyFact.generateSecret(spec);
            key = new SecretKeySpec(tmp.getEncoded(), "AES");
            encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
            encoder.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	
            decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decoder.init(Cipher.DECRYPT_MODE, key, ivSpec);
	        
            for (i = 0; i < creds.size(); i++)
	        {
                    changeCreds(credNames.second().get(i), creds.get(i).first(), new String(creds.get(i).second()));
	        }
	
        } catch (Exception e) {
            System.out.println("Issues re-encrypting using new password!");
            e.printStackTrace();
        }
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
            .key("command").value("LOGOUT")
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


    // Precondition: already logged out. 
    // Postcondition: Close connection.
    protected static Response exit(){
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
        byte[] hashedPassword;
        byte[] passwordBytes = charToBytes(password);

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
            .key("command").value("DEL")
            .key("password").value(new String(hashedPassword))
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
            username = null;
        }

        return err;
    }
}
