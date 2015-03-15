package client;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;

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
    protected static int login(String username, char[] password) throws IOException {

        String packet = "ATHN," + username + "," + new String(password);
        int len = packet.length();

        sockWriter.println(packet);
        System.out.println(packet);
            
        return 0;
    }

    /* Register a new account.
     * pre: user is not logged in
     * post: creates an account on the server with the associated account data.
     * It also authenticates that account immediately (user is logged in).
     */
    protected static int register(String username, char[] password, String email) {
        return 0;
    }

    /* Add a set of credentials to an account.
     * pre: user is logged in
     * post: server adds that set of credentials to the account.
     */
    protected static int addCreds(String service, String username, String password) {
        return 0;
    }

    /* Get credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: a list of the requested credentials, or all credentials.
     */
    protected static String[] requestCreds(String service) {
        return null;
    }

    /* Deletes a set of credentials from the server.
     * pre: user is logged in, credentials exist on the server
     * post: that set of credentials no longer exists on the server
     */
    protected static int deleteCreds(String service) {
        return 0;
    }

    /* Changes the username and password for a certain set of credentials.
     * pre: user is logged in, credentials exist on the server
     * post: the username or password for that set of credentials is changed
     */
    protected static int changeCreds(String service, String username, String password) {
        return 0;
    }

    /* Logs out the user.
     * pre: user is logged in
     * post: user is no longer logged in
     */
    protected static int logout() {
        return 0;
    }
}
