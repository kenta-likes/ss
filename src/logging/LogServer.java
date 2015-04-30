package logging;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.security.*;

import util.Consts.*;
import util.Response;
import javax.xml.bind.DatatypeConverter;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;

public class LogServer {

    protected static SecretKey key;
    protected static byte[] keyBytes;
    protected static String HOSTNAME;
    protected static String ADMIN_PASSWORD;
    protected static boolean newKey;

    public static void main(String[] args) {
        String ksName = "audit_ts.jks"; //server side keystore
        char ksPass[] = "systemsecurity".toCharArray();
        char ctPass[] = "systemsecurity".toCharArray();

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
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, new SecureRandom());
            SSLServerSocketFactory ssf = sc.getServerSocketFactory();
            SSLServerSocket s
                = (SSLServerSocket) ssf.createServerSocket(8889);

            ExecutorService executor = Executors.newFixedThreadPool(8);

            /* Read in key. */
            File keyFile = new File("logkey.conf");
            if (keyFile.exists() && !keyFile.isDirectory()) {
                BufferedReader f = new BufferedReader(new FileReader("logkey.conf"));
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
            BufferedWriter writer = new BufferedWriter(new FileWriter("log.txt"));
            writer.write(entry + "\t" + tag);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        iterateKey();
        return Response.SUCCESS;
    }

    protected static String getLog() {
        return null;
    }

    private static boolean authenticate(String logLine, String tagLine) {
        byte[] logBytes = DatatypeConverter.parseBase64Binary(logLine);
        byte[] tag = DatatypeConverter.parseBase64Binary(tagLine);
        byte[] tagFromEntry;
        boolean equal = true;

        try {
            /* Re-MAC the message and check the two tags are equal. */
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            tagFromEntry = mac.doFinal(logBytes);

            if (tag.length != tagFromEntry.length)
                return false;

            for (int i = 0; i < tag.length; i++) {
                equal &= (tag[i] == tagFromEntry[i]);
            }

            return equal;
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
            w.flush();
            w.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
