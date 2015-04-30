package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.ArrayList;
import java.util.List;

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

public class Server {

    /* Monitor for producer-consumer behavior of ServerConnections and LogThread. */
    protected static List<String> logLines;
    protected static final Lock logLock = new ReentrantLock();
    protected static final Condition logCondition = logLock.newCondition();
    
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
            ExecutorService executor = Executors.newFixedThreadPool(8);

            Runnable logger = new Logger(args[0], "auditstore.jks", "systemsecurity".toCharArray());
            
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
}
