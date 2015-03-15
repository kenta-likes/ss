package server;



import java.io.IOException;

/**
 * Generate an SSL key for the server. 
 * 
 * TODO: Modify these commands so they run without the user having
 * to input their name and identifiers on the console.
 * @author mitchvogel
 *
 */
public class ServerKeyGen {
	public static void main(String args[]) {
		Runtime r = Runtime.getRuntime();
		Process p;
		try {
			p = r.exec("keytool -genkey -alias server_full -keypass ServerKey "
   + "-keystore server.jks -storepass ServerJKS ");
			p.waitFor();
			p = r.exec("keytool -export -alias server_full -file server_pub.crt " 
   + "-keystore server.jks -storepass ServerJKS ");
			p.waitFor();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
