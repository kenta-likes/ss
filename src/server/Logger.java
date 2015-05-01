package server;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.xml.bind.DatatypeConverter;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
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
        
    private byte[] entry, keyBytes, iv;
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
            File keyFile = new File("s_logkey.conf");

            rand = SecureRandom.getInstance("SHA1PRNG");
            keyBytes = new byte[32];
                    
            rand.nextBytes(keyBytes);
            key = new SecretKeySpec(keyBytes, "AES");

            iv = new byte[16];
            rand.nextBytes(iv);

            /* Three different MessageDigest/MAC objects for different purposes.
             * keyGenerator is used to make encryption keys.
             * signer is used to generate tags from log lines.
             * iterator is used to iterate the authentication key.
             */
            keyGenerator = MessageDigest.getInstance("SHA-384");
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
            
            SSLSocket c = (SSLSocket) fact.createSocket(logHostname, Consts.LOGSERVER_PORT);
            c.setEnabledCipherSuites(Consts.ACCEPTED_SUITES);
            c.startHandshake();

            /* Try to close the socket cleanly on CTRL-C. */
            Runtime.getRuntime().addShutdownHook(new Thread(){public void run(){
                try {
                    new JSONWriter(sockWriter).object().key("command").value("CLOSE")
                        .endObject();

                    sockWriter.println();
                    sockWriter.flush();
                    
                    c.close();
                } catch (IOException e) { /* failed :( */ }
            }});
            
            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            sockWriter = new PrintWriter(c.getOutputStream(), true);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        try {
            String k = DatatypeConverter.printBase64Binary(keyBytes);
            String i = DatatypeConverter.printBase64Binary(iv);

            JSONWriter w = new JSONWriter(sockWriter);
            w.object()
                .key("command").value("KEY")
                .key("key").value(k)
                .key("iv").value(i)
                .endObject();

            sockWriter.println();
            sockWriter.flush();

            JSONObject resp = new JSONObject(sockReader.readLine());
                
            if (resp.getString("response").equals("FAIL")) {
                keyBytes = DatatypeConverter.parseBase64Binary(resp.getString("key"));
                iv = DatatypeConverter.parseBase64Binary(resp.getString("iv"));
            }

        } catch (Exception e) {
            System.out.println("Error: failed to synchronize key with log server!");
            e.printStackTrace();
            return;
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

                /* Pop the first entry off the log list. */
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
            byte[] encryptionKeyBytes = java.util.Arrays.copyOf(keyGenerator.digest(keyBytes), 32);
            SecretKey encryptionKey = new SecretKeySpec(encryptionKeyBytes, "AES");

            encoder.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));

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
        SecretKey macKey = new SecretKeySpec(keyBytes, "HmacSHA256");

        try {
            signer.init(macKey);

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

            digest = iterator.digest(iv);
            iv = java.util.Arrays.copyOf(digest, 16);

            key = new SecretKeySpec(keyBytes, "AES/CBC/PKCS5Padding");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
