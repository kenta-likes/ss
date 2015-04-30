package logging;

import javax.net.ssl.*;

import java.io.*;
import util.Pair;
import util.Response;
import org.json.*;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;

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

            while (true) {
                while ((m = r.readLine()) != null) {
                    js = new JSONWriter(w);
                    req = new JSONObject(m);

                    String command = req.getString("command");
                    Response resp;

                    switch (command) {
                    case "ADD":
                        /* Make sure we are contacted by the right person.
                         * If not, terminate connection. */
                        if (!socket.getInetAddress().getHostName().equals(LogServer.HOSTNAME)) {
                            resp = Response.FAIL;
                            return;
                        } else {
                            String entry = req.getString("entry");
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
                        
                        if (password.equals(LogServer.ADMIN_PASSWORD)) {
                            resp = Response.SUCCESS;
                            authenticated = true;
                        } else
                            resp = Response.FAIL;
                        
                        js.object()
                            .key("response").value(resp.name())
                            .endObject();

                        break;

                    case "GET":
                        String log;
                        js = js.object();
                            
                        if (!authenticated)
                            resp = Response.FAIL;
                        else {
                            log = LogServer.getLog();
                            js = js.key("log").value(log);
                            resp = Response.SUCCESS;
                        }

                        js.key("response").value(resp.name())
                            .endObject();

                        break;

                    case "KEY":
                        if (LogServer.newKey == true)
                            resp = Response.FAIL;
                        else {
                            resp = Response.SUCCESS;
                            String base64Key = req.getString("key");
                            LogServer.keyBytes = DatatypeConverter.parseBase64Binary(base64Key);
                            LogServer.key = new SecretKeySpec(LogServer.keyBytes, "AES/CBC/PKCS5PAdding");
                        }

                        js.object()
                            .key("response").value(resp)
                            .endObject();
                    }

                    w.newLine();
                    w.flush();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
