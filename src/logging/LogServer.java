package logging;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LogServer {

    public static void main(String[] args) {
        String ksName = "auditstore.jks"; //server side keystore
        char ksPass[] = "systemsecurity".toCharArray();
        char ctPass[] = "systemsecurity".toCharArray();
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

            while (true) {
                SSLSocket c = (SSLSocket) s.accept();
                Runnable connection = new LogConnection(c);
                executor.execute(connection);
            }
         
        } catch (Exception e) {
            //System.err.println(e.toString());
            e.printStackTrace();
        }
    }

    public static void log() {
        
    }
}
