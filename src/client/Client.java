package client;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;

public class Client {
   public static void main(String[] args) {
      BufferedReader in = new BufferedReader(
         new InputStreamReader(System.in));
      PrintStream out = System.out;
      SSLSocketFactory f = 
         (SSLSocketFactory) SSLSocketFactory.getDefault();
      try {
         SSLSocket c =
           (SSLSocket) f.createSocket("localhost", 8888);
         printSocketInfo(c);
         c.startHandshake();
         BufferedWriter w = new BufferedWriter(
            new OutputStreamWriter(c.getOutputStream()));
         BufferedReader r = new BufferedReader(
            new InputStreamReader(c.getInputStream()));
         String m = null;

         // This is probably where we want to add our shell initialization
         
         while ((m=r.readLine())!= null) {
            out.println(m);
            m = in.readLine();
            w.write(m,0,m.length());
            w.newLine();
            w.flush();
         }
         w.close();
         r.close();
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
    protected int login(String username, char[] password) {
        return 0;
    }

    /* Register a new account.
     * pre: user is not logged in
     * post: creates an account on the server with the associated account data.
     * It also authenticates that account immediately (user is logged in).
     */
    protected int register(String username, char[] password, String email) {
        return 0;
    }

    /* Add a set of credentials to an account.
     * pre: user is logged in
     * post: server adds that set of credentials to the account.
     */
    protected int addCreds(String service, String username, String password) {
        return 0;
    }

    /* Get credentials from the server.
     * pre: user is logged in
     * post: none
     * returns: a list of the requested credentials, or all credentials.
     */
    protected String[] requestCreds(String service) {
        return 0;
    }

    /* Deletes a set of credentials from the server.
     * pre: user is logged in, credentials exist on the server
     * post: that set of credentials no longer exists on the server
     */
    protected int deleteCreds(String service) {
        return 0;
    }

    /* Changes the username and password for a certain set of credentials.
     * pre: user is logged in, credentials exist on the server
     * post: the username or password for that set of credentials is changed
     */
    protected int changeCreds(String service, String username, String password) {
        return 0;
    }

    /* Logs out the user.
     * pre: user is logged in
     * post: user is no longer logged in
     */
    protected int logout() {
        return 0;
    }
}
