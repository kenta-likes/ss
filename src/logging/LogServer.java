package logging;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.security.*;

import util.Consts;
import util.Response;
import javax.xml.bind.DatatypeConverter;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.lang.StringBuilder;
import java.security.spec.KeySpec;

public class LogServer {

    protected static SecretKey key;
    protected static byte[] keyBytes, iv;
    protected static String HOSTNAME;
    protected static String ADMIN_PASSWORD = "systemsecurity";
    protected static boolean newKey;

    public static void main(String[] args) {
        String ksName = "5430_keystore.jks"; //server side keystore
        char ksPass[] = "security".toCharArray();
        char ctPass[] = "security".toCharArray();

        if (args.length < 1) {
            System.out.println("error: did not receive hostname argument");
            return;
        }

        /* To make sure we are connected to the right people... */
        HOSTNAME = args[0];
        
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(ksName), ksPass);
            KeyManagerFactory kmf =
                KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, ctPass);
            
            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(kmf.getKeyManagers(), null, new SecureRandom());
            SSLServerSocketFactory ssf = sc.getServerSocketFactory();
            SSLServerSocket s
                = (SSLServerSocket) ssf.createServerSocket(Consts.LOGSERVER_PORT);
            s.setEnabledCipherSuites(Consts.ACCEPTED_SUITES);

            ExecutorService executor = Executors.newFixedThreadPool(8);

            /* Read in key. */
            File keyFile = new File("ls_logkey.conf");
            File originalKeyFile = new File("original_logkey.conf");

            /* Make sure we have the original and the current key. */
            if (keyFile.exists() && !keyFile.isDirectory() && originalKeyFile.exists() && !originalKeyFile.isDirectory()) {
                BufferedReader f = new BufferedReader(new FileReader("ls_logkey.conf"));
                keyBytes = DatatypeConverter.parseBase64Binary(f.readLine());
                newKey = false;
                
                key = new SecretKeySpec(keyBytes, "AES/CBC/PKCS5Padding");
            } else {
                newKey = true;
            }

            while (true) {
                SSLSocket c = (SSLSocket) s.accept();
                Runnable connection = new logging.LogConnection(c);
                executor.execute(connection);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static Response log(String entry, String tag) {
        
        /* Check signature is OK. */
        if (!authenticate(entry, tag))
            return Response.FAIL;

        /* Write line to disk. */
        try {
            /* Make sure our writer is in append mode. */
            BufferedWriter writer = new BufferedWriter(new FileWriter("log.txt", true));
            writer.write(entry + "\t" + tag);
            writer.newLine();
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        iterateKey();
        return Response.SUCCESS;
    }

    protected static String getLog(int lines) {
        SecretKey k;
        byte[] authKeyBytes, iv, encKeyBytes;
        Cipher decoder;
        StringBuilder b = new StringBuilder();
        MessageDigest keyGenerator, iterator;
        

        try {
            keyGenerator = MessageDigest.getInstance("SHA-384");
            iterator = MessageDigest.getInstance("SHA-256");
            
            BufferedReader r = new BufferedReader(new FileReader("original_logkey.conf"));
            String encKey = r.readLine();
            String encIV = r.readLine();

            authKeyBytes = DatatypeConverter.parseBase64Binary(encKey);
            iv = DatatypeConverter.parseBase64Binary(encIV);

            decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");

            r = new BufferedReader(new FileReader("log.txt"));

            for (int i = 0; i < lines; i++) {
                 // tag is a tab character after the message. Discard it.
                String line = r.readLine();

                if (line == null)
                    break;
                
                String base64EncLine = line.split("\t")[0];

                byte[] encLine = DatatypeConverter.parseBase64Binary(base64EncLine);

                byte[] digest = keyGenerator.digest(authKeyBytes);
                
                encKeyBytes = java.util.Arrays.copyOf(digest, 32);
                k = new SecretKeySpec(encKeyBytes, "AES");

                decoder.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
                String decLine = new String(decoder.doFinal(encLine));

                b.append(decLine);
                b.append("\n");

                digest = iterator.digest(authKeyBytes);
                authKeyBytes = java.util.Arrays.copyOf(digest, 32);
                
                digest = iterator.digest(iv);
                iv = java.util.Arrays.copyOf(digest, 16);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return b.toString();
    }

    private static boolean authenticate(String logLine, String tagLine) {
        byte[] logBytes = DatatypeConverter.parseBase64Binary(logLine);
        byte[] tag = DatatypeConverter.parseBase64Binary(tagLine);
        byte[] tagFromEntry;
        SecretKey macKey = new SecretKeySpec(keyBytes, "HmacSHA256");

        try {
            /* Re-MAC the message and check the two tags are equal. */
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(macKey);
            tagFromEntry = mac.doFinal(logBytes);

            return java.util.Arrays.equals(tag, tagFromEntry);
            
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    /* Hash key bytes with SHA-256 and update the key. */
    private static void iterateKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(keyBytes);

            /* Use only first 256 bits of hash. */
            keyBytes = java.util.Arrays.copyOf(digest, 32);

            key = new SecretKeySpec(keyBytes, "AES/CBC/PKCS5Padding");

            String base64Key = DatatypeConverter.printBase64Binary(keyBytes);
            BufferedWriter w = new BufferedWriter(new FileWriter("ls_logkey.conf"));
            w.write(base64Key);
            w.newLine();

            digest = md.digest(iv);
            iv = java.util.Arrays.copyOf(digest, 16);
            String base64IV = DatatypeConverter.printBase64Binary(iv);
            
            w.write(base64IV);
            w.newLine();
            
            w.flush();
            w.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
