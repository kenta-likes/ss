package client;

public class ClientKeyGen {
	
	public static void main(String args[]) {
		Runtime r = Runtime.getRuntime();
		Process p;
		try {
			p = r.exec("keytool -genkey -alias client_full -keypass ClientKey " +
   "-keystore client.jks -storepass ClientJKS");
			p.waitFor();
			p = r.exec("keytool -export -alias client_full -file client_pub.crt" + 
   " -keystore client.jks -storepass ClientJKS");
			p.waitFor();
			// get public certificate from the server
			p = r.exec("keytool -import -alias cerver_pub -file server_pub.crt" 
   + " -keystore client.jks -storepass ClientJKS");
			p.waitFor();
		} catch (Exception e) {
		// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
