package client;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import server.ServerConnection.Response;
import java.util.List;

public class Client {
    
    private static PrintWriter sockWriter;
    private static BufferedReader sockReader;
    
    public static void main(String[] args) {
        PrintStream out = System.out;
        SSLSocketFactory f = 
            (SSLSocketFactory) SSLSocketFactory.getDefault();

        sockReader = null;
        sockWriter = null;
      
        try {
            SSLSocket c =
                (SSLSocket) f.createSocket("localhost", 8888);
            printSocketInfo(c);
            c.startHandshake();

            sockReader = new BufferedReader(new InputStreamReader(c.getInputStream()));
            sockWriter = new PrintWriter(c.getOutputStream(), true);

            Shell.run();

            c.close();
        } catch (IOException e) {
            System.err.println(e.toString());
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

    /* Login with the master username/password set. */
    protected static Response login(String username, char[] password) {

        String packet = "ATHN," + username + "," + new String(password);
        int len = packet.length();

        sockWriter.println(packet);
        System.out.println(packet);
            
        return Response.SUCCESS;
    }

    /* Register a new account.
     * pre: user is not logged in
     * post: creates an account on the server with the associated account data.
     * It also authenticates that account immediately (user is logged in).
     */
    protected static Response register(String username, char[] password, String email) {
        return Response.SUCCESS;
    }

    /* Add a set of credentials to an account.
     * pre: user is logged in
     * post: server adds that set of credentials to the account.
     */
    protected static Response addCreds(String service, String username, String password) {
        return Response.SUCCESS;
    }

    /* Get credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: error code + the requested credentials.
     */
    protected static Pair<Response, String> requestCreds(String service) {
        return null;
    }

    /* Get all credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: a list of all credentials associated with the user's account
     */
    protected static Pair<Response, List<String>> requestAllCreds() {
        return null;
    }

    /* Deletes a set of credentials from the server.
     * pre: user is logged in, credentials exist on the server
     * post: that set of credentials no longer exists on the server
     */
    protected static Response deleteCreds(String service) {
        return Response.SUCCESS;
    }

    /* Changes the username and password for a certain set of credentials.
     * pre: user is logged in, credentials exist on the server
     * post: the username or password for that set of credentials is changed
     */
    protected static Response changeCreds(String service, String username, String password) {
        return Response.SUCCESS;
    }

    /* Logs out the user.
     * pre: user is logged in
     * post: user is no longer logged in
     */
    protected static Response logout() {
        return Response.SUCCESS;
    }
}
