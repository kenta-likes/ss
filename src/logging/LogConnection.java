package logging;

import javax.net.ssl.*;

import java.io.*;
import util.Pair;
import util.Response;
import org.json.*;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

public class LogConnection implements Runnable {

    protected SSLSocket socket;
    protected String wd;
    protected boolean authenticated = false;

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

            while ((m = r.readLine()) != null) {
                js = new JSONWriter(w);
                req = new JSONObject(m);

                String command = req.getString("command");
                Response resp;

                switch (command) {
                case "CLOSE":
                    return;
                    
                case "ADD":
                    /* Make sure we are contacted by the right person.
                     * If not, terminate connection. */
                    if (!socket.getInetAddress().getHostName().equals(LogServer.HOSTNAME)) {
                        resp = Response.FAIL;
                        return;
                    } else {
                        String entry = req.getString("line");
                        String tag = req.getString("tag");
                        resp = LogServer.log(entry, tag);
                    }

                    js.object()
                        .key("response").value(resp.name())
                        .endObject();

                    /* If we fail to authenticate, then terminate connection. */
                    if (resp == Response.FAIL)
                        return;

                    break;

                    /* Admin is trying to log in. Check against admin PW. */
                case "AUTH":
                    String password = req.getString("password");
                    byte[] toHash = new byte[32 + password.length()];

                    System.arraycopy(password.getBytes(), 0, toHash, 0, password.length());
                    System.arraycopy(LogServer.salt, 0, toHash, password.length(), 32);

                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] digest = md.digest(toHash);

                        if (Arrays.equals(digest, LogServer.stored_pass)) {
                            resp = Response.SUCCESS;
                            authenticated = true;
                        } else
                            resp = Response.FAIL;

                    } catch (Exception e) {
                        resp = Response.FAIL;
                        e.printStackTrace();
                    }
                        
                    js.object()
                        .key("response").value(resp.name())
                        .endObject();

                    break;

                case "GET":
                    String log;
                    String lines = req.getString("lines");

                    js = js.object();

                    if (!authenticated)
                        resp = Response.FAIL;
                    else {
                        if (lines.equals("all")) {
                            
                            log = LogServer.getLog(LogServer.lines);
                            js = js.key("log").value(log);
                            resp = Response.SUCCESS;
                            
                        } else {
                            
                            System.out.print(lines);
                            try {
                                log = LogServer.getLog(Integer.parseInt(lines));
                                js = js.key("log").value(log);
                                resp = Response.SUCCESS;
                            } catch (NumberFormatException e) {
                                resp = Response.FAIL;
                            }
                        }
                    }

                    js.key("response").value(resp.name())
                        .endObject();

                    break;

                case "KEY":
                    String base64Key;
                    String base64IV;
                    js = js.object();
                    
                    if (LogServer.newKey == false) {
                        resp = Response.FAIL;
                        base64Key = DatatypeConverter.printBase64Binary(LogServer.keyBytes);
                        base64IV = DatatypeConverter.printBase64Binary(LogServer.iv);
                        
                        js = js.key("key").value(base64Key)
                            .key("iv").value(base64IV);
                        
                    } else {
                        resp = Response.SUCCESS;
                        base64Key = req.getString("key");
                        base64IV = req.getString("iv");
                        
                        LogServer.keyBytes = DatatypeConverter.parseBase64Binary(base64Key);
                        LogServer.key = new SecretKeySpec(LogServer.keyBytes, "AES/CBC/PKCS5PAdding");
                        LogServer.iv = DatatypeConverter.parseBase64Binary(base64IV);
                        LogServer.newKey = false;

                        try {
                            BufferedWriter w1 = new BufferedWriter(new FileWriter("original_logkey.conf"));
                            w1.write(base64Key);
                            w1.newLine();
                            w1.write(base64IV);
                            w1.newLine();
                            w1.flush();
                            w1.close();
                        } catch (Exception e) {
                            e.printStackTrace();
                            resp = Response.FAIL;
                        }
                    }
                    
                    js.key("response").value(resp)
                        .endObject();
                }

                w.newLine();
                w.flush();

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
