package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;


public class ServerConnection implements Runnable {
	static final char REG = 0;
	static final char AUTH = 1;
	
	//response type
	public enum Response{
		SUCCESS, FAIL, WRONG_PASS, WRONG_USR
	}
	
	SSLSocket socket;
	String username; //user associated with this account
	boolean timed_out = false;

         
    public ServerConnection(SSLSocket s) {
    	this.socket = s;
    	
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
             while (true){
	             while ((m=r.readLine())!= null) {
	            	//check for authenticated user
	            	if (username != null){
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
	                } else { //only allow registration or authentication
	                }
	             }
	             if (timed_out) //TODO this is placeholder, change later for actual timeout check
	            	 break;
             }
             w.close();
             r.close();
             socket.close();
    	} catch (Exception e)
    	{
    		e.printStackTrace();
    	}
    }
    
    /*
     * Create new account on server.
     * */
	public Response createAccount(String username, String password) {
		return Response.FAIL;
	}
    
    /*
     * Change password for this user
     * */
    public Response changeAccountPassword(String old_password, String new_password){
    	return Response.FAIL;
    }
    
    /*
     * Delete this account
     * */
    public Response deleteAccount(String password){
    	return Response.FAIL;
    }
	
    /*
     * Authenticate user to system
     * */
    public Response authAccount(String username, String password){
    	return Response.FAIL;
    }
    
    /*
     * Returns a list of services for which credentials stored on server.
     * (Delimited by commas?)
     * */
    public String retrieveCredentials(){
    	return "";
    }
    
    /*
     * Get password for specific service
     * */
    public String getPassword(String service_name){
    	return "";
    }
    
    /*
     * Adds new credentials
     * */
    public Response addCredential(String service_name, String username, String password){
    	return Response.FAIL;
    }
    
    /*
     * Updates credentials with new password
     * */
    public Response updateCredential(String service_name, String password){
    	return Response.FAIL;
    }
    
    /*
     * Deletes specific credential for specified service
     * */
    public Response deleteCredential(String service_name){
    	return Response.FAIL;
    }
    
    /*
     * Checks master password against salted + hashed value stored on server
     * */
    public boolean checkPassword(String password){
    	return false;
    }
    
	   
	public void getAccountCredentialsList(String accountName) {
		   
	}
}
