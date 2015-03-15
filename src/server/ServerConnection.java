package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;

import javax.net.ssl.SSLSocket;

import client.Pair;

import java.util.Hashtable;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.File;
import java.security.SecureRandom;

public class ServerConnection implements Runnable {
	static final int SALT_LEN = 32; //use # of bytes of SHA-256 output
	
	//response type
	public enum Response {
            SUCCESS,
            FAIL, /*for generic "server error" type responses*/
            WRONG_PASS, /*user entered password is incorrect*/
            WRONG_USR, /*wrong username entered for authentication*/
            NO_SVC,/* used when the requested service is not found. */
            NAUTH, /* used when the user is not logged in, but tries an op other than login */
            USER_EXISTS, /*when username is already taken at registration*/
            CRED_EXISTS /*when adding, the credentials already exist for that service*/
	}
	
	SSLSocket socket;
	private String username; //user associated with this account
	boolean timed_out = false; //TODO think about this later...
	Hashtable<String,Pair<String,String>> user_table;
         
    public ServerConnection(SSLSocket s) {
    	this.socket = s;
    	user_table = new Hashtable<String,Pair<String,String>>();
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
    
    public String saltAndHash(String password, String salt) throws NoSuchAlgorithmException {
    	byte[] toHash = new byte[SALT_LEN + password.length()];
		System.arraycopy(password, 0, toHash, 0, password.length());
		System.arraycopy(salt, 0, toHash, password.length(), SALT_LEN);
		// Hash the master password
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(toHash);
		return new String(messageDigest.digest());
    }
    
    
    /*
     * Create new account on server
     * Randomly generates a salt and stores a hashed
     * master password.
     * */
	public Response createAccount(String username, String password) throws Exception {
		// Directory already exists
		// Note: Not thread-safe 
		if (new File(username).isDirectory() || username == null || password == null
				|| username.isEmpty() || password.isEmpty()){
			return Response.FAIL;
		}
		// Create a new directory
		new File(username).mkdirs();
        
		// Generate a salt randomly and append it to master password. 
		// Salt = 32 bytes since we use SHA-256
		byte[] salt = new SecureRandom().generateSeed(SALT_LEN);
		String hashedpassword;
		try{
			hashedpassword = saltAndHash(password, new String(salt));
		} catch (NoSuchAlgorithmException e){
			return Response.FAIL; //should never happen
		}
		// Write hashed master password and the salt to a file named "master.txt"
		PrintWriter writer = new PrintWriter(username.concat("/master.txt"), "UTF-8");
		writer.println(hashedpassword);
		writer.println(salt);
		writer.close();
		
		/*create new file for credentials as well*/
		PrintWriter creds_writer = new PrintWriter(username.concat("/stored_credentials.txt"), "UTF-8");
		creds_writer.close();
		return Response.SUCCESS;
	}
    
    /*
     * Change password for this user
     * */
    public Response changeAccountPassword(String old_password, String new_password){
    	if (this.authAccount(this.username, old_password) == Response.FAIL){
    		return Response.FAIL;
    	}
    	
		// Generate a salt randomly and append it to master password. 
		// Salt = 32 bytes since we use SHA-256
		byte[] salt = new SecureRandom().generateSeed(SALT_LEN);
		String hashedpassword;
		try{
			hashedpassword = saltAndHash(new_password, new String(salt));
		} catch (NoSuchAlgorithmException e){
			return Response.FAIL; //should never happen
		}
		
		// Write hashed master password and the salt to a file named "master.txt"
		// Note: will overwrite the old file
		PrintWriter writer;
		try {
			writer = new PrintWriter(username.concat("/master.txt"), "UTF-8");
			writer.println(hashedpassword);
			writer.println(salt);
			writer.close();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
			return Response.FAIL; //should never happen
		} catch (UnsupportedEncodingException e2) {
			e2.printStackTrace();
			return Response.FAIL; //should never happen
		}
		
    	return Response.SUCCESS;
    }
    
    /*
     * Delete this account
     * */
    public Response deleteAccount(String password){
    	if (this.authAccount(this.username, password) == Response.FAIL){
    		return Response.FAIL;
    	}
 
    	// Note: guaranteed that this account exists
    	// Delete the account
    	File directory = new File(username);
    	String[] entries = directory.list();
    	
    	// Delete all the files in this directory
    	for (String s: entries){
    		File currentFile = new File(directory.getPath(), s);
    		currentFile.delete();
    	}
    	
    	// delete the directory 
    	directory.delete();
    	return Response.SUCCESS;
    }
	
    /*
     * Authenticate user to system
     * */
    public Response authAccount(String username, String password){
    	// Directory DNE TODO: check with other fxns
		// Note: Not thread-safe 
		if ( !(new File(username).isDirectory())){
			return Response.FAIL;
		}
		String salt, stored_pass;
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader("/master.txt"));
			stored_pass = reader.readLine();
			salt = reader.readLine();
			reader.close();
			String hashedpassword = saltAndHash(password, salt);
			if (!hashedpassword.equals(stored_pass))
				return Response.WRONG_PASS;

			this.username = username;
			//load hash table with user's credentials
			BufferedReader cred_reader = new BufferedReader(new FileReader("/stored_credentials.txt"));
			String line;
			while ( (line=cred_reader.readLine()) != null ){
				String[] curr_cred = line.split(",");
				if (curr_cred.length != 3){
					cred_reader.close();
					return Response.FAIL;
				}
				user_table.put(curr_cred[0], new Pair<String,String>(curr_cred[1], curr_cred[2]));
			}
			cred_reader.close();
			return Response.SUCCESS;
		} catch (NoSuchAlgorithmException e1){ //should never happen
			e1.printStackTrace();
			return Response.FAIL;
		} catch (IOException e2) {
			e2.printStackTrace();
			return Response.FAIL;
		}
    }
    
    /*
     * Returns a list of services for which credentials stored on server.
     * Delimited by commas
     * */
    public Pair<Response,String> retrieveCredentials(){
		String cred_list = "";
		for (String k : user_table.keySet()){
			if (!cred_list.isEmpty())
				cred_list += "," + k;
			else
				cred_list = k;
		}
		return new Pair<Response,String>(Response.SUCCESS, cred_list);
    }
    
    /*
     * Get password for specific service
     * */
    public Pair<Response,String> getPassword(String service_name){
    	if (!user_table.containsKey(service_name)){ //credentials not listed in server
    		return new Pair<Response,String>(Response.NO_SVC, "");
    	}
    	return new Pair<Response,String>(Response.SUCCESS, user_table.get(service_name).second());
    }
    
    /*
     * Adds new credentials
     * */
    public Response addCredential(String service_name, String username, String password){
    	if (user_table.contains(service_name))
    		return Response.CRED_EXISTS;
    	user_table.put(service_name, new Pair<String,String>(username, password));
    	return Response.SUCCESS;
    }
    
    /*
     * Updates credentials with new password
     * */
    public Response updateCredential(String service_name, String password){
		if (!user_table.contains(service_name))
			return Response.NO_SVC;
		user_table.put(service_name, new Pair<String,String>(username, password));
		return Response.SUCCESS;
    }
    
    /*
     * Deletes specific credential for specified service
     * */
    public Response deleteCredential(String service_name){
		if (!user_table.contains(service_name))
			return Response.NO_SVC;
		user_table.remove(service_name);
		return Response.SUCCESS;
    }
}
