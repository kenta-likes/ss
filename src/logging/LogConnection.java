package logging;

import javax.net.ssl.*;

import java.io.*;
import util.Pair;
import util.Response;
import org.json.*;
import javax.xml.bind.DatatypeConverter;

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
                        /* Make sure we are contacted by the right person. */
                        if (!socket.getInetAddress().getHostName().equals(LogServer.HOSTNAME))
                            resp = Response.FAIL;
                        else {
                            
                            String entry = req.getString("entry");
                            String tag = req.getString("tag");
                            resp = LogServer.log(entry, tag);
                        }

                        js.object()
                            .key("response").value(resp.name())
                            .endObject();

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
                        }

                        js.key("response").value(resp.name())
                            .endObject();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
