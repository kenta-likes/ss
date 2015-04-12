package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.io.File;

import javax.net.ssl.SSLSocket;

public class ServerConnection implements Runnable {
	SSLSocket socket;

         
    // public ServerConnection(SSLSocket s) {
    // 	this.socket = s;
    	
    // }
       public ServerConnection() {
        
    }
    
    public void run() {
    	try {
    		BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                socket.getOutputStream()));
             BufferedReader r = new BufferedReader(new InputStreamReader(
                socket.getInputStream()));
             String m = "Welcome to SSL Reverse Echo Server."+
                " Please type in some words.";
             w.write(m,0,m.length());
             w.newLine();
             w.flush();
             while ((m=r.readLine())!= null) {
                if (m.equals(".")) break;
                char[] a = m.toCharArray();
                int n = a.length;
                for (int i=0; i<n/2; i++) {
                   char t = a[i];
                   a[i] = a[n-1-i];
                   a[n-i-1] = t;
                }
                w.write(a,0,n);
                w.newLine();
                w.flush();
             }
             w.close();
             r.close();
             socket.close();
    	} catch (Exception e)
    	{
    		e.printStackTrace();
    	}
    }
    

	public void makeAccount(String username, String password) throws Exception{
        new File(username).mkdirs();
        File file = new File(username.concat("/master"));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(password.getBytes());
        String hashedpassword = new String(messageDigest.digest());

        PrintWriter writer = new PrintWriter(username.concat("/master"), "UTF-8");
        writer.println(hashedpassword);
        writer.close();


		   
	}
	 

	public void getAccountCredentialsList(String accountName) {

		 

	}

    // for test
    public static void main(String args[]) throws Exception{
        ServerConnection serverConnection = new ServerConnection();
        serverConnection.makeAccount("cs5430", "clarkson");
  }


}
