package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;

import javax.net.ssl.SSLSocket;

import util.*;

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
    protected Hashtable<String,Pair<String,String>> user_table;
    MessageDigest messageDigest;
         
    public ServerConnection(SSLSocket s) {
    	this.socket = s;
    	user_table = new Hashtable<String,Pair<String,String>>();
    	messageDigest = null;
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
                    if (username != null){
                        
                        switch (command) {
                        case "ADD":
                            String service = req.getString("service");
                            String sName = req.getString("username");
                            String sPass = req.getString("password");
                            js.object()
                                .key("response").value(addCredential(service, sName, sPass)
                                                       .name())
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

            r.close();
            socket.close();
    	} catch (Exception e)
            {
    		e.printStackTrace();
            }
    }
    
    public String responseGetString(Response r){
    	switch (r){
	    	case SUCCESS: return "SUCCESS";
	    	case FAIL: return "INTERNAL ERROR";
	    	case WRONG_PASS: return "WRONG PASSWORD";
	    	case WRONG_USR: return "USERNAME DOES NOT EXIST";
	    	case NO_SVC: return "CREDENTIAL DOES NOT EXIST";
	    	case NAUTH: return "USER NOT LOGGED IN";
	    	case USER_EXISTS: return "USERNAME IS TAKEN";
	    	case CRED_EXISTS: return "CREDENTIAL ALREADY TAKEN";
	    	default: break;
    	}
    	return "";
    }
    
    /*
     * Helper function for salting and hashing master passwords
     * */
    public byte[] saltAndHash(String password, byte salt[]) throws NoSuchAlgorithmException {
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
     * Helper function for logging
     * */
    public void log_result(String method_name, Response res){
        try {
            Date date = new Date();
            PrintWriter logger = new PrintWriter(username.concat("/log.txt"), "UTF-8");
            logger.println(date.toString() + ": " + responseGetString(res) + " on " + method_name);
            logger.flush();
            logger.close();
        } catch (IOException e){
            e.printStackTrace();
        }
    }
    
    
    /*
     * Create new account on server
     * Randomly generates a salt and stores a hashed
     * master password.
     * */

    public Response createAccount(String username, String password) {
        // Directory already exists
        // Note: Not thread-safe 
        if (new File(username).isDirectory()){
            //log_result("Create Account", Response.FAIL);
            return Response.FAIL;
        }
        // Create a new directory
        new File(username).mkdirs();
        
        // Generate a salt randomly and append it to master password. 
        // Salt = 32 bytes since we use SHA-256
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt); //get bytes for salt
        byte[] hashedpassword;
        try {
            hashedpassword = saltAndHash(password, salt);
            
            FileOutputStream writer = new FileOutputStream(username.concat("/master.txt"));
            writer.write(hashedpassword);
            writer.write(salt);
            writer.flush();
            writer.close();
    		
            /*create new file for credentials*/
            PrintWriter creds_writer = new PrintWriter(username.concat("/stored_credentials.txt"), "UTF-8");
            creds_writer.close();
            
            /*create new file for logs*/
            PrintWriter logger = new PrintWriter(username.concat("/log.txt"), "UTF-8");
            logger.close();
        } catch (Exception e){
            e.printStackTrace();
            return Response.FAIL;
        }

        /* set the session to be logged in successfully */
        this.username = username;

        log_result("Create Account", Response.SUCCESS);

        return Response.SUCCESS;
    }
    
    /*
     * Change password for this user
     * */
    public Response changeAccountPassword(String old_password, String new_password){
    	if (this.authAccount(this.username, old_password) == Response.FAIL){
            log_result("Change Account Password", Response.FAIL);
            return Response.FAIL;
    	}
    	
        // Generate a salt randomly and append it to master password. 
        // Salt = 32 bytes since we use SHA-256
        byte[] salt = new SecureRandom().generateSeed(SALT_LEN);
        byte[] hashedpassword;
        try{
            hashedpassword = saltAndHash(new_password, salt);
        } catch (NoSuchAlgorithmException e){
            log_result("Change Account Password", Response.FAIL);
            return Response.FAIL; //should never happen
        }
		
        // Write hashed master password and the salt to a file named "master.txt"
        // Note: will overwrite the old file
        FileOutputStream writer;
        try {

            writer = new FileOutputStream(username.concat("/master.txt"));
            writer.write(hashedpassword);
            writer.write(salt);
            writer.flush();
            writer.close();
        } catch (IOException e1) {
            e1.printStackTrace();
            log_result("Change Account Password", Response.FAIL);
            return Response.FAIL; //should never happen
        }
        log_result("Change Account Password", Response.SUCCESS);
    	return Response.SUCCESS;
    }
    
    /*
     * Delete this account and log out the user.
     * */
    public Response deleteAccount(String password){
    	if (this.authAccount(this.username, password) == Response.FAIL){
            log_result("Delete Account", Response.FAIL);
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
        log_result("Delete Account", Response.SUCCESS);
        username = null;
    	return Response.SUCCESS;
    }
	
    /*
     * Authenticate user to system
     * */
    public Response authAccount(String username, String password){
    	// Directory DNE TODO: check with other fxns
        // Note: Not thread-safe 
        if ( !(new File(username).isDirectory())){
            log_result("Authenticate Account", Response.FAIL);
            return Response.FAIL;
        }
        byte salt[] = new byte[SALT_LEN];
        byte stored_pass[] = new byte[32];
        FileInputStream reader;
        try {
            reader = new FileInputStream(username.concat("/master.txt"));
            reader.read(stored_pass, 0, 32);
            //reader.read(); //reads newline TODO: Fix later
            reader.read(salt,0,SALT_LEN);
            reader.close();
            
            byte[] hashedpassword = saltAndHash(password, salt);
            if (!Arrays.equals(hashedpassword,stored_pass)){
                log_result("Authenticate Account", Response.WRONG_PASS);
                return Response.WRONG_PASS;
            }

            this.username = username;
            //load hash table with user's credentials
            BufferedReader cred_reader = new BufferedReader(
                    new FileReader(username.concat("/stored_credentials.txt")));
            String line;
            while ( (line=cred_reader.readLine()) != null ){
                String[] curr_cred = line.split(",");
                if (curr_cred.length != 3){
                    cred_reader.close();
                    log_result("Authenticate Account", Response.FAIL);
                    return Response.FAIL;
                }
                System.out.println("Loaded creds for " + curr_cred[0]);
                user_table.put(curr_cred[0], new Pair<String,String>(curr_cred[1], curr_cred[2]));
            }
            cred_reader.close();
            log_result("Authenticate Account", Response.SUCCESS);
            return Response.SUCCESS;
        } catch (NoSuchAlgorithmException e1){ //should never happen
            e1.printStackTrace();
            log_result("Authenticate Account", Response.FAIL);
            return Response.FAIL;
        } catch (IOException e2) {
            e2.printStackTrace();
            log_result("Authenticate Account", Response.FAIL);
            return Response.FAIL;
        }
    }
    
    /*
     * Returns a list of services for which credentials stored on server.
     * Delimited by commas
     * */
    public Pair<Response,ArrayList<String>> retrieveCredentials(){
        ArrayList<String> cred_list = new ArrayList<String>();
        for (String k : user_table.keySet()){
                cred_list.add(k);
        }
        log_result("Get Credential List", Response.SUCCESS);
        return new Pair<Response,ArrayList<String>>(Response.SUCCESS, cred_list);
    }
    
    /*
     * Get password for specific service
     * */
    public Pair<Response, Pair<String, String>> getPassword(String service_name){
    	if (!user_table.containsKey(service_name)){ //credentials not listed in server
            log_result("Get Credential", Response.NO_SVC);
            return new Pair<Response,Pair<String, String>>(Response.NO_SVC,
                                                           new Pair<String, String>("", ""));
    	}
        log_result("Get Credential", Response.SUCCESS);
    	return new Pair<Response,
            Pair<String, String>>(Response.SUCCESS, user_table.get(service_name));
    }
    
    /*
     * Adds new credentials
     * */
    public Response addCredential(String service_name, String stored_username, String stored_password){
    	if (user_table.containsKey(service_name))
            return Response.CRED_EXISTS;
    	user_table.put(service_name, new Pair<String,String>(stored_username, stored_password));
    	return Response.SUCCESS;
    }
    
    /*
     * Updates credentials with new password
     * */
    public Response updateCredential(String service_name, String new_username, String new_stored_pass){
        if (!user_table.containsKey(service_name)) {
            System.out.println("Service " + service_name + " not in table.");
            return Response.NO_SVC;
        }
        user_table.put(service_name, new Pair<String,String>(new_username, new_stored_pass)); //TODO FIX username!!
        return Response.SUCCESS;
    }
    
    /*
     * Deletes specific credential for specified service
     * */
    public Response deleteCredential(String service_name){
        if (!user_table.containsKey(service_name))
            return Response.NO_SVC;
        user_table.remove(service_name);
        return Response.SUCCESS;
    }

    public Response logout() {
        try
            (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter
                                                                  (username +
                                                                   "/stored_credentials.txt"
                                                                   , false))))
            {
                for (String s : user_table.keySet()) {
                    Pair<String, String> creds = user_table.get(s);
                    out.println(s + "," + creds.first() + "," + creds.second());
                }
            } catch (IOException e) {
            // TODO: Need something to log here...
            return Response.FAIL;
        }

        // Also should log here
        return Response.SUCCESS;
            
    }
}
