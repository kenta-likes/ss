package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.io.File;

import javax.net.ssl.SSLSocket;

import util.Pair;
import util.Response;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.File;
import java.security.SecureRandom;

import org.json.*;

public class ServerConnection implements Runnable {
    static final int SALT_LEN = 32; //use # of bytes of SHA-256 output
		
    protected SSLSocket socket;
    protected String username; //user associated with this account
    protected boolean timed_out = false; //TODO think about this later...
    protected Hashtable<String, Pair<String, String>> user_table;
    protected MessageDigest messageDigest;
    protected String curr_dir;
         

    public ServerConnection(SSLSocket s) {
    	this.socket = s;
    	messageDigest = null;
    	curr_dir = "";
    }
    
    public void run() {
    	try {
            BufferedWriter w = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            JSONWriter js;
            BufferedReader r = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String m, command;
            JSONObject req;
            while (true){
                while ((m = r.readLine()) != null) {

                    js = new JSONWriter(w);
                    req = new JSONObject(m);
                    command = req.getString("command");
                    
                    //check for authenticated user
                    //System.out.println("ServerConnection: command=" +command);
                    if (username != null){
                        
                        switch (command) {
                        
                        case "ATHN":
                        case "RGST":
                            js.object()
                                .key("response").value(Response.DUP_LOGIN)
                                .endObject();
                            break;
                            
                        case "ADD":
                            String service = req.getString("service");
                            String sName = req.getString("username");
                            String sPass = req.getString("password");
                            js.object()
                                .key("response").value(addCredential(service,sName,sPass).name())
                                .endObject();
                            break;
                        case "GET1":
                            ArrayList<String> creds;
                            Response resp;
                            Pair<Response, ArrayList<String>> pair = retrieveCredentials();
                            resp = pair.first();
                            creds = pair.second();

                            js.object()
                                .key("response").value(resp.name());

                            if (resp == Response.SUCCESS) {
                                js.key("data").object()
                                    .key("credentials").array();

                                for (String s : creds)
                                    js.value(s);

                                js.endArray();

                                js.endObject();
                            }

                            js.endObject();
                            break;
                            
                        case "GET2":
                            Pair<Response, Pair<String, String>> cred;
                            service = req.getString("service");
                            cred = getPassword(service);
                            resp = cred.first();

                            js.object()
                                .key("response").value(resp.name())
                                .key("username").value(cred.second().first())
                                .key("password").value(cred.second().second())
                                .endObject();
                            break;
                            
                        case "DEL":
                            String password = req.getString("password");
                        resp = deleteAccount(password);

                        js.object()
                            .key("response").value(resp.name())
                            .endObject();
                        
                        break;
                        
                        case "CHNG":
                            String oldPass = req.getString("oldPassword");
                        String newPass = req.getString("newPassword");
                        resp = changeAccountPassword(oldPass, newPass);

                        js.object()
                            .key("response").value(resp.name())
                            .endObject();
                        break;
                        
                        case "REMV":
                            service = req.getString("service");
                        resp = deleteCredential(service);
                        js.object()
                            .key("response").value(resp.name())
                            .endObject();
                        break;
                        
                        case "EDIT":
                            service = req.getString("service");
                            sName = req.getString("username");
                            sPass = req.getString("password");
                            resp = updateCredential(service, sName, sPass);
                            
                            js.object()
                                .key("response").value(resp.name())
                                .endObject();

                            break;

                        case "CLOSE":
                            resp = logout();
                            js.object()
                                .key("response").value(resp.name())
                                .endObject();

                            if (resp == Response.SUCCESS) {
                                w.newLine();
                                w.flush();
                                socket.close();
                                return;
                            }
                            
                        default:
                        	//System.out.println("username is not null: command is "+command);
                        	// TODO: this is a stub to prevent json from breaking
                        	js.object()
                            .key("response").value("NAUTH")
                            .endObject();
                        }

                        w.newLine();
                        w.flush();
                        
                    } else { //only allow registration or authentication
                        switch (command) {
                        case "ATHN":
                            String authName = req.getString("username");
                            String authPass = req.getString("password");
                            Response resp = authAccount(authName, authPass);
                            js.object()
                                .key("response").value(resp.name())
                                .endObject();
                            
                            break;
                            
                        case "RGST":
                            String regName = req.getString("username");
                            String regPass = req.getString("password");
                            String email = req.getString("email");

                            resp = createAccount(regName, regPass);
                            js.object()
                                .key("response").value(resp.name())
                                .endObject();

                            break;
                        case "CLOSE":
                            logout();
                            js.object()
                            .key("response").value("SUCCESS")
                            .endObject();
                            break;
                        default: js.object()
                            .key("response").value("NAUTH")
                            .endObject();
                        }

                        w.newLine();
                        w.flush();
                    }
                }
                if (timed_out) //TODO this is placeholder, change later for actual timeout check
                    break;
            }
            //write back to file, then remove reference to the hash table etc.
            user_table = null;
            username = null;
            logCenter(username ,"Logout", Response.SUCCESS);
            r.close();
            socket.close();
    	} catch (Exception e)
            {
    		e.printStackTrace();
            }
    }
    
    
    /*
     * Helper fxn for simple string input checking
     * */
    protected boolean checkInput(String inputs[]){
        for (String s : inputs){
            if (s == null || s.isEmpty()) //disallow directory
                return false;
        }
        return true;
    }
    
    /*
     * Helper fxn for checking valid usernames
     * */
    protected boolean checkUsernameFormat(String usr){
        return !(usr.contains("/") || usr.contains("\\"));
    }
    
    /*
     * helper fxn for checking data format to not contain tab spaces
     * */
    protected boolean checkDataFormat(String data[]){
        for (String d : data){
            if (d.isEmpty() || d.contains("\t")) //disallow directory
                return false;
        }
        return true;
    }
    
    /*
     * Helper function for salting and hashing master passwords
     * */
    protected byte[] saltAndHash(String password, byte salt[]) throws NoSuchAlgorithmException {
    	byte[] toHash = new byte[SALT_LEN + password.length()];
        
        System.arraycopy(password.getBytes(), 0, toHash, 0, password.length());
        System.arraycopy(salt, 0, toHash, password.length(), SALT_LEN);
        
        // Hash the master password
        //MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        if (messageDigest == null){
            messageDigest = MessageDigest.getInstance("SHA-256");
        }
        messageDigest.update(toHash);
        
        return messageDigest.digest();
    }
    
    /*
     * Helper function for logging for a specific user
     * Should be used for everything associated with the user
     * */
    protected void logUserResult(String method_name, Response res){
        try {
            Date date = new Date();
            //PrintWriter logger = new PrintWriter(curr_dir.concat("/log.txt"), "UTF-8");
            String ip_addr = socket == null || socket.getRemoteSocketAddress() == null ? "N/A" :
                socket.getRemoteSocketAddress().toString();
            PrintWriter logger = new PrintWriter(new BufferedWriter
                    (new FileWriter(curr_dir.concat("/user_log.txt"), true)));
            logger.println(date.toString()
                    + "\t" + ip_addr
                    + "\t" + method_name
                    + "\t" + res.name() );
            logger.flush();
            logger.close();
        } catch (IOException e){
            e.printStackTrace();
        }
    }
    
    /*
     * Helper function for logging for the server
     * */

    protected void logCenter(String user, String method_name, Response res){
        try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("centerlog.txt", true)))) {
        	Date date = new Date();
        	if (user==null){user = "N/A";}
        	String ip_addr = socket == null || socket.getRemoteSocketAddress() == null ? "N/A" :
        	                socket.getRemoteSocketAddress().toString();
        	out.println(user
        	        + "\t" + date.toString()
        	        + "\t" + ip_addr
        	        + "\t" + method_name
        	        + "\t" + res.name());
        	out.flush();
        	out.close();
        }catch (IOException e) {
        	e.printStackTrace();
        }
    }
    
    
    /*
     * Create new account on server
     * Randomly generates a salt and stores a hashed
     * master password.
     * Assumes: username and password are not null
     * Assumes: username and password are valid (we haven't defined valid yet)
     * */
    protected Response createAccount(String new_usr, String password) {
        if (!checkInput(new String[]{new_usr, password})){
            return Response.WRONG_INPT;
        }
        if (!this.checkUsernameFormat(new_usr)){
            return Response.BAD_FORMAT;
        }
        // Directory already exists
        // Note: Not thread-safe 
        if (new File("users/" + new_usr).isDirectory()){
        	//logCenter(username ,"Create Account", Response.FAIL);
            return Response.USER_EXISTS;
        }
        // Create a new directory
        curr_dir = "users/" + new_usr;
        new File(curr_dir).mkdirs();
        
        // Generate a salt randomly and append it to master password. 
        // Salt = 32 bytes since we use SHA-256
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt); //get bytes for salt
        byte[] hashedpassword;
        try {
            hashedpassword = saltAndHash(password, salt);
            
            FileOutputStream writer = new FileOutputStream(curr_dir.concat("/master.txt"));
            writer.write(hashedpassword);
            writer.write(salt);
            writer.flush();
            writer.close();
    		
            /*create new file for credentials*/
            PrintWriter creds_writer = new PrintWriter(curr_dir.concat("/stored_credentials.txt"), "UTF-8");
            creds_writer.close();
            
            /*create new file for logs*/
            PrintWriter logger = new PrintWriter(curr_dir.concat("/user_log.txt"), "UTF-8");
            logger.close();
        } catch (Exception e){
            e.printStackTrace();
            return Response.FAIL;
        }

        user_table = new Hashtable<String, Pair<String, String>>();
        /* set the session to be logged in successfully */
        username = new_usr;
        
        //Logging
		logCenter(username, "Create Account", Response.SUCCESS);
        logUserResult("Create Account", Response.SUCCESS); // ?

        return Response.SUCCESS;
    }
    
    /*
     * Change password for this user
     * */
    protected Response changeAccountPassword(String old_password, String new_password){
        if (!checkInput(new String[]{old_password, new_password})){
            return Response.WRONG_INPT;
        }
    	if (this.authAccount(this.username, old_password) != Response.SUCCESS){
    		// Logging
    		logUserResult("Change Account Password", Response.FAIL);
    		return Response.FAIL;
    	}
    	
        // Generate a salt randomly and append it to master password. 
        // Salt = 32 bytes since we use SHA-256
        byte[] salt = new SecureRandom().generateSeed(SALT_LEN);
        byte[] hashedpassword;
        try{
            hashedpassword = saltAndHash(new_password, salt);
        } catch (NoSuchAlgorithmException e){
            return Response.FAIL; //should never happen
        }
		
        // Write hashed master password and the salt to a file named "master.txt"
        // Note: will overwrite the old file
        FileOutputStream writer;
        try {
            writer = new FileOutputStream(curr_dir.concat("/master.txt"));
            writer.write(hashedpassword);
            writer.write(salt);
            writer.flush();
            writer.close();
        } catch (IOException e1) {
            e1.printStackTrace();
            logUserResult("Change Account Password", Response.FAIL);
            return Response.FAIL; //should never happen
        }
        logUserResult("Change Account Password", Response.SUCCESS);
    	return Response.SUCCESS;
    }
    
    /*
     * Delete this account and log out the user.
     * */
    protected Response deleteAccount(String password){
        if (!checkInput(new String[]{password})){
            return Response.WRONG_INPT;
        }
    	Response r = this.authAccount(this.username, password);
    	if (r != Response.SUCCESS){
    		// Logging
    		logCenter(this.username,"Delete Account", r);
            return r;
    	}
 
    	// Note: guaranteed that this account exists
    	// Delete the account
    	File directory = new File(curr_dir);
    	String[] entries = directory.list();
    	if (entries != null) {
    		// Delete all the files in this directory
    		for (String s: entries){
    			File currentFile = new File(directory.getPath(), s);
    			currentFile.delete();
    		}
    	}
    	
    	// delete the directory 
    	directory.delete();
    	
    	// Logging
    	logCenter(this.username,"Delete Account", Response.SUCCESS);
        username = null;
        user_table = null;
    	return Response.SUCCESS;
    }
	
    /*
     * Authenticate user to system
     * */
    protected Response authAccount(String auth_usr, String password){
        if (!checkInput(new String[]{auth_usr, password})){
            return Response.WRONG_INPT;
        }
        if (!this.checkUsernameFormat(auth_usr)){
            return Response.BAD_FORMAT;
        }
        // Note: Not thread-safe 
        if ( !(new File("users/" + auth_usr).isDirectory())){
        	// Logging
        	logCenter(auth_usr,"Authenticate Account", Response.WRONG_INPT);
            return Response.WRONG_INPT;
        }
        
        byte salt[] = new byte[SALT_LEN];
        byte stored_pass[] = new byte[32];
        FileInputStream reader;
        try {
            reader = new FileInputStream(("users/" + auth_usr).concat("/master.txt"));
            reader.read(stored_pass, 0, 32);
            reader.read(salt,0,SALT_LEN);
            reader.close();
            
            byte[] hashedpassword = saltAndHash(password, salt);
            if (!Arrays.equals(hashedpassword,stored_pass)){
            	// Logging
            	logCenter(auth_usr, "Authenticate Account", Response.WRONG_INPT);
                logUserResult("Authenticate Account", Response.WRONG_INPT);
                return Response.WRONG_INPT;
            }

            //init hashtable
            user_table = new Hashtable<String, Pair<String, String>>();
            username = auth_usr;
            curr_dir = "users/" + auth_usr;
            //load hash table with user's credentials
            BufferedReader cred_reader = new BufferedReader(
                    new FileReader(curr_dir.concat("/stored_credentials.txt")));
            String line;
            while ( (line=cred_reader.readLine()) != null ){
                String[] curr_cred = line.split("\t");

                if (curr_cred.length != 3){
                    cred_reader.close();
                    logUserResult("Authenticate Account", Response.FAIL);
                    return Response.FAIL;
                }
                //System.out.println("Loaded creds for " + curr_cred[0]);
                user_table.put(curr_cred[0], new Pair<String,String>(curr_cred[1], curr_cred[2]));
            }
            cred_reader.close();
            
            // Logging
            logCenter(auth_usr,"Authenticate Account", Response.SUCCESS);
            logUserResult("Authenticate Account", Response.SUCCESS);
            return Response.SUCCESS;
        
        } catch (NoSuchAlgorithmException e1){ //should never happen
            e1.printStackTrace();
            logCenter(auth_usr,"Authenticate Account", Response.FAIL);
            logUserResult("Authenticate Account", Response.FAIL);
            return Response.FAIL;
        } catch (IOException e2) {
            e2.printStackTrace();
            logCenter(auth_usr,"Authenticate Account", Response.FAIL);
            logUserResult("Authenticate Account", Response.FAIL);
            return Response.FAIL;
        }
    }
    
    /*
     * Returns a list of services for which credentials stored on server.
     * Delimited by commas
     * */
    protected Pair<Response,ArrayList<String>> retrieveCredentials(){
        ArrayList<String> cred_list = new ArrayList<String>();
        for (String k : user_table.keySet()){
                cred_list.add(k);
        }
        logUserResult("Get Credential List", Response.SUCCESS);
        return new Pair<Response,ArrayList<String>>(Response.SUCCESS, cred_list);
    }
    
    /*
     * Get password for specific service
     * */
    protected Pair<Response, Pair<String, String>> getPassword(String service_name){
        if (!checkInput(new String[]{service_name})){
            return new Pair<Response,Pair<String,String>>(Response.WRONG_INPT, null);
        }
        if (!this.checkDataFormat(new String[] {service_name})){
            return new Pair<Response,Pair<String,String>>(Response.BAD_FORMAT,null);
        }
    	if (!user_table.containsKey(service_name)){ //credentials not listed in server
            logUserResult("Get Credential", Response.NO_SVC);
            return new Pair<Response,Pair<String, String>>(Response.NO_SVC, null);
    	}
        logUserResult("Get Credential", Response.SUCCESS);
    	return new Pair<Response,
            Pair<String, String>>(Response.SUCCESS, user_table.get(service_name));
    }
    
    /*
     * Adds new credentials
     * */
    protected Response addCredential(String service_name, String stored_username, String stored_password){
        if (!checkInput(new String[]{stored_username, stored_password})){
            return Response.WRONG_INPT;
        }
        if (!this.checkDataFormat(new String[] {service_name, stored_username, stored_password})){
            return Response.BAD_FORMAT;
        }
    	if (user_table.containsKey(service_name))
            return Response.CRED_EXISTS;
    	user_table.put(service_name, new Pair<String,String>(stored_username, stored_password));
    	
    	return Response.SUCCESS;
    }
    
    /*
     * Updates credentials with new password
     * */
    protected Response updateCredential(String service_name, String new_username, String new_stored_pass){
        if (!checkInput(new String[]{new_username, new_stored_pass})){
            return Response.WRONG_INPT;
        }
        if (!this.checkDataFormat(new String[] {service_name, new_username, new_stored_pass})){
            return Response.BAD_FORMAT;
        }
        if (!user_table.containsKey(service_name)) {
            //System.out.println("Service " + service_name + " not in table.");
            return Response.NO_SVC;
        }
        user_table.put(service_name, new Pair<String,String>(new_username, new_stored_pass));
        return Response.SUCCESS;
    }
    
    /*
     * Deletes specific credential for specified service
     * */
    protected Response deleteCredential(String service_name){
        if (!checkInput(new String[]{service_name})){
            return Response.WRONG_INPT;
        }
        if (!this.checkDataFormat(new String[] {service_name})){
            return Response.BAD_FORMAT;
        }
        if (!user_table.containsKey(service_name))
            return Response.NO_SVC;
        user_table.remove(service_name);
        return Response.SUCCESS;
    }


    protected Response logout() {

        try{
            BufferedWriter writer = new BufferedWriter(
                    new FileWriter(curr_dir.concat("/stored_credentials.txt")));
            for (String k : user_table.keySet()){
               writer.write(k + "\t" +  user_table.get(k).first() + "\t" + user_table.get(k).second() + "\n");
            }
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            return Response.FAIL;
        }
        // Also should log here
        return Response.SUCCESS;
            
    }
>>>>>>> 578337fcf6edce6c09d6a7ed93d8c2ef3e6607e5
}
