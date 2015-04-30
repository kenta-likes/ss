package server;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.xml.bind.DatatypeConverter;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Lock;

import org.json.*;

import javax.net.ssl.*;

import util.Consts;

public class Logger implements Runnable {
    private BufferedReader sockReader;
    private PrintWriter sockWriter;
        
    private byte[] entry, keyBytes;
    private String encodedEntry, logHostname, logKSName;
    private char[] logPassphrase;
    private Cipher encoder;
    private MessageDigest iterator, keyGenerator;
    private Mac signer;
    private SecureRandom rand;
    private boolean newKey;
    private SecretKey key;

    public Logger(String logHostname, String logKSName, char[] logPassphrase) {
        this.logHostname = logHostname;
        this.logKSName = logKSName;
        this.logPassphrase = logPassphrase;

        try {
            File keyFile = new File("logkey.conf");
            byte[] keyBytes;

            /* Look for an existing authentication key. */
            if (keyFile.exists() && !keyFile.isDirectory()) {
                BufferedReader b = new BufferedReader(new FileReader(keyFile));
                String base64Key = b.readLine();

                keyBytes = DatatypeConverter.parseBase64Binary(base64Key);
                newKey = false;
                    
            } else {
                /* No key file found.  Generate a new key. */
                rand = SecureRandom.getInstance("SHA1PRNG");
                keyBytes = new byte[32];
                    
                rand.nextBytes(keyBytes);
                newKey = true;
            }

            /* Three different MessageDigest/MAC objects for different purposes.
             * keyGenerator is used to make encryption keys.
             * signer is used to generate tags from log lines.
             * iterator is used to iterate the authentication key.
             */
            keyGenerator = MessageDigest.getInstance("SHA-1");
            iterator = MessageDigest.getInstance("SHA-256");
            signer = Mac.getInstance("HmacSHA256");

            encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
                
        } catch (Exception e) {
            /* Uh oh... */
            e.printStackTrace();
        }
    }

    public void run() {
        try {
            /* Set up socket & connection. */
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(logKSName), logPassphrase);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(keyStore);
            
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            context.init(null, trustManagers, new SecureRandom());
            SSLSocketFactory fact = context.getSocketFactory();
            
            SSLSocket c = (SSLSocket) fact.createSocket(logHostname, 8889);
            c.setEnabledCipherSuites(Consts.ACCEPTED_SUITES);
            c.startHandshake();

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            sockWriter = new PrintWriter(c.getOutputStream(), true);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        if (newKey == true) {
            try {
                SecureRandom keyRand = SecureRandom.getInstance("SHA1PRNG");
                keyBytes = new byte[32];
                keyRand.nextBytes(keyBytes);

                String k = DatatypeConverter.printBase64Binary(keyBytes);

                JSONWriter w = new JSONWriter(sockWriter);
                w.object()
                    .key("command").value("KEY")
                    .key("key").value(k)
                    .endObject();

                sockWriter.println();
                sockWriter.flush();

                String resp = sockReader.readLine();
                
                if (resp.equals("FAIL")) {
                    System.out.println("Please reconfigure logserver & server keys!");
                    return;
                }
            } catch (Exception e) {
                System.out.println("New key transmission failed.");
                e.printStackTrace();
                return;
            }
        }

        /* Logging loop.  Wait for new entries in the logLine list. When they arrive,
         * dequeue, encrypt, sign, and submit to log server.
         */
        while (true) {
            String line;
                
            /* Monitor begins here for dequeueing items from logLines list. S/O to EGS.
             * Also, if we get Heisenbugs in this module you can sacrifice me to the gods
             * of Synchronization for not following proper monitor syntax.
             * - Kyle
             */
            Server.logLock.lock();
            try {
                
                while (Server.logLines.isEmpty())
                    Server.logCondition.await();

                line = Server.logLines.remove(0);
                    
            } catch (InterruptedException e) {
                e.printStackTrace();
                continue;
            } finally {
                Server.logLock.unlock();
            }

            String encLine = encryptLogEntry(line);
            String tag = signLogEntry(encLine);

            JSONWriter js = new JSONWriter(sockWriter);

            js.object()
                .key("command").value("ADD")
                .key("line").value(encLine)
                .key("tag").value(tag)
                .endObject();

            sockWriter.println();
            sockWriter.flush();

            JSONObject resp;
            try {
                resp = new JSONObject(sockReader.readLine());
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
                
            if (resp.getString("response").equals("FAIL")) {
                System.out.println("Logging thread was rejected, shutting logging down!");
                return;
            }

            iterateKey();
        }
    }

    /* Use to encrypt log messages.  This builds an encryption key based on a hash of the
     * authentication key.
     *
     * It does not iterate the authentication key - this should only be done after the
     * message is successfully logged.
     */
    private String encryptLogEntry(String logEntry) {
        try {
            byte[] encryptionKeyBytes = keyGenerator.digest(keyBytes);
            SecretKeySpec encryptionKeySpec = new SecretKeySpec(encryptionKeyBytes, "AES");
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance("AES/CBC/PKCS5Padding");
            SecretKey encryptionKey = keyFact.generateSecret(encryptionKeySpec);
                
            encoder.init(Cipher.ENCRYPT_MODE, encryptionKey);

            byte[] entry = encoder.doFinal(logEntry.getBytes());
            String encodedEntry = DatatypeConverter.printBase64Binary(entry);

            return encodedEntry;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /* Used to sign log messages.  It uses the authentication key. */
    private String signLogEntry(String logEntry) {
        byte[] tag;
        String encodedTag;

        try {
            signer.init(key);

            tag = signer.doFinal(DatatypeConverter.parseBase64Binary(logEntry));
            encodedTag = DatatypeConverter.printBase64Binary(tag);

            return encodedTag;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void iterateKey() {
        try {
            byte[] digest = iterator.digest(keyBytes);
            keyBytes = java.util.Arrays.copyOf(digest, 32);

            key = new SecretKeySpec(keyBytes, "AES/CBC/PKCS5Padding");

            String base64Key = DatatypeConverter.printBase64Binary(keyBytes);
            BufferedWriter w = new BufferedWriter(new FileWriter("s_logkey.conf"));
            w.write(base64Key);
            w.newLine();
            w.flush();
            w.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
