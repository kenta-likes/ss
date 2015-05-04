package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.ArrayList;
import java.util.List;
import java.util.*;

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
import util.Pair;
import util.Response;

public class Server {

    /* Monitor for producer-consumer behavior of ServerConnections and LogThread. */
    protected static List<String> logLines;
    protected static final Lock logLock = new ReentrantLock();
    protected static final Condition logCondition = logLock.newCondition();
    /*all the sharing transactions*/
    protected static Hashtable<String, ArrayList<ServerConnection.Triple<String,String,String>>> transaction_table =
                new Hashtable<String, ArrayList<ServerConnection.Triple<String,String,String>>>();
    protected static final Lock transaction_lock = new ReentrantLock();
    /*all acl and shared transactions*/
    protected static Hashtable<String, Pair<Hashtable<String,ArrayList<String>>, Hashtable<String, Pair<String,String>>>> shared_user_table =
                new Hashtable<String, Pair<Hashtable<String, ArrayList<String>>, Hashtable<String, Pair<String,String>>>>();
    
    public static void main(String[] args) {
        String ksName = "5430_keystore.jks"; //server side keystore
        char ksPass[] = "security".toCharArray();
        char ctPass[] = "security".toCharArray();

        if (args.length == 0) {
            System.out.println("err: no log server hostname detected.");
            return;
        }

        logLines = new ArrayList<String>();
        
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(ksName), ksPass);
            KeyManagerFactory kmf = 
                KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, ctPass);
            
            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(kmf.getKeyManagers(), null, new SecureRandom());
            SSLServerSocketFactory ssf = sc.getServerSocketFactory();
            SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(Consts.SERVER_PORT);
            s.setEnabledCipherSuites(Consts.ACCEPTED_SUITES);
            //printServerSocketInfo(s);
            ExecutorService executor = Executors.newFixedThreadPool(9);

            Runnable logger = new Logger(args[0], "server/5430ts.jks", "security".toCharArray());
            executor.execute(logger);

            initSharedUserTable(); 

            while (true) {
                SSLSocket c = (SSLSocket) s.accept();
                Runnable connection = new ServerConnection(c);
                executor.execute(connection);
            }
        } catch (Exception e) {
            //System.err.println(e.toString());
            e.printStackTrace();
        }
    }

    private static void printServerSocketInfo(SSLServerSocket s) {
        System.out.println("Server socket class: "+s.getClass());
        System.out.println("   Socker address = "
                           +s.getInetAddress().toString());
        System.out.println("   Socker port = "
                           +s.getLocalPort());
        System.out.println("   Need client authentication = "
                           +s.getNeedClientAuth());
        System.out.println("   Want client authentication = "
                           +s.getWantClientAuth());
        System.out.println("   Use client mode = "
                           +s.getUseClientMode());
    }

    /*Initializes the acl table and shared table for all the users*/
    private static void initSharedUserTable(){
      try {
        /*load ACL/shared credentials into a hashtable for all users*/
        String[] dirs = (new File(System.getProperty("user.dir") + "/users")).list();
        for (String username : dirs){
          String curr_dir = System.getProperty("user.dir") + "/users/" + username;
          File user_dir = new File(curr_dir);
          if (user_dir.isDirectory()){
            System.out.println("Doing loading for user: " + username);
            Hashtable<String, ArrayList<String>> acl_table = new Hashtable<String, ArrayList<String>>();
            Hashtable<String, Pair<String,String>> shared_table = new Hashtable<String, Pair<String, String>>();
            shared_user_table.put(username, 
                        new Pair<Hashtable<String, ArrayList<String>>, Hashtable<String, Pair<String,String>>>(acl_table, shared_table)); //put into the shared table for access
            // load hash table with user's credentials
            String line;
            BufferedReader shared_cred_reader = new BufferedReader(new FileReader(curr_dir + "/shared_credentials.txt"));
            while ((line = shared_cred_reader.readLine()) != null) {
                String[] curr_shared_cred = line.split("\t");
                if (curr_shared_cred.length != 3) {
                    shared_cred_reader.close();
                }
                // System.out.println("Loaded creds for " + curr_cred[0]);
                shared_table.put(curr_shared_cred[0],
                               new Pair<String, String>(curr_shared_cred[1],
                                                        curr_shared_cred[2]));
            }
            shared_cred_reader.close();

            /*load hashtable for acl*/
            BufferedReader acl_reader = new BufferedReader(new FileReader(curr_dir + "/acl.txt"));
            while ((line = acl_reader.readLine()) != null) {
                String[] curr_acl = line.split("\t");

                //get all the service names that this user has access to
                ArrayList<String> service_list = new ArrayList<String>();
                for (int i = 1; i < curr_acl.length; i++){
                  service_list.add(curr_acl[i]);
                }
                acl_table.put(curr_acl[0], service_list);
            }
            acl_reader.close();
          }
        }
      } catch (IOException e){
        e.printStackTrace();
      }
    }
}
