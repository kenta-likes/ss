package server;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.*;

public class Server {
	
   public static void main(String[] args) {
      String ksName = "5430_keystore.jks"; //server side keystore
      char ksPass[] = "security".toCharArray();
      char ctPass[] = "security".toCharArray();
      try {
         KeyStore ks = KeyStore.getInstance("JKS");
         ks.load(new FileInputStream(ksName), ksPass);
         KeyManagerFactory kmf = 
         KeyManagerFactory.getInstance("SunX509");
         kmf.init(ks, ctPass);
         SSLContext sc = SSLContext.getInstance("TLS");
         sc.init(kmf.getKeyManagers(), null, new SecureRandom());
         SSLServerSocketFactory ssf = sc.getServerSocketFactory();
         SSLServerSocket s 
            = (SSLServerSocket) ssf.createServerSocket(8888);

         printServerSocketInfo(s);
         
         ExecutorService executor = Executors.newFixedThreadPool(8);
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
