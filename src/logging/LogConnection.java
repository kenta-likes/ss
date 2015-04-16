package logging;

import javax.net.ssl.*;

import java.io.*;
import util.Pair;
import util.Response;
import org.json.*;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.security.MessageDigest;

public class LogConnection implements Runnable {

    protected SSLSocket socket;
    protected String username = null;
    protected String wd;
    protected SecretKey key;
    protected byte[] keyBytes;
    
    public LogConnection(SSLSocket s) {
        this.socket = s;
    }

    public void run() {
        try {
            BufferedWriter w = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader r = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String m;
            JSONWriter js;
            JSONObject req;

            while (true) {
                while ((m = r.readLine()) != null) {
                    js = new JSONWriter(w);
                    req = new JSONObject(m);

                    String command = req.getString("command");

                    switch (command) {
                    case "LOGUSR":
                        String authName = req.getString("username");
                        String entry = req.getString("entry");
                        String tag = req.getString("tag");
                        Response resp = addEntry(authName, entry, tag);

                        js.object()
                            .key("response").value(resp.name())
                            .endObject();
                    
                        break;

                    case "NEWUSR":
                        authName = req.getString("username");
                        
                        String key = req.getString("key");
                        resp = createLog(authName, key);

                        js.object()
                            .key("response").value(resp.name())
                            .endObject();

                        break;
                    }
                } 
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected Response addEntry(String authName, String entry, String tag) {
        if (username == null) {
            username = authName;
            wd = username;

            try {
                BufferedReader f = new BufferedReader(new FileReader(wd + "/key.conf"));
                keyBytes = DatatypeConverter.parseBase64Binary(f.readLine());

            } catch (Exception e) {
                e.printStackTrace();
                return Response.FAIL;
            }

        } else if (!username.equals(authName)) {
            return Response.FAIL;
        }

        /* Make sure the tag is OK. */
        if (!authenticate(entry, tag))
            return Response.FAIL;

        /* Write out the log line to disk. */
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(username + "/log.txt"));
            writer.write(entry + "\t" + tag);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        /* Iterate key hash here... */
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(keyBytes);

            /* Use only first 256 bits of hash. */
            keyBytes = java.util.Arrays.copyOf(digest, 32);
            
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance("AES");
            KeySpec spec = new SecretKeySpec(keyBytes, "AES/CBC/PKCS5Padding");
            key = keyFact.generateSecret(spec);            
        } catch (Exception e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        return Response.SUCCESS;
    }

    protected Response createLog(String authName, String keyStr) {
        byte[] key;
        wd = authName;
        new File(wd).mkdirs();
        
        keyBytes = DatatypeConverter.parseBase64Binary(keyStr);
        try {
            FileWriter writer = new FileWriter(wd + "/key.conf");
            writer.write(keyStr);
            writer.write(keyStr);
            writer.flush();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        return Response.SUCCESS;
    }

    private boolean authenticate(String logLine, String tagLine) {
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
}
