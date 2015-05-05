package server;

import java.security.KeyStore;

import javax.net.ssl.*;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

import javax.xml.bind.DatatypeConverter;

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
import java.io.File;

import util.Carrier;
import util.Pair;
import util.Response;
import util.Consts;

import java.util.*;

import javax.mail.*;
import javax.mail.internet.*;
import javax.activation.*;

import org.json.*;

public class ServerConnection implements Runnable {
    static final int SALT_LEN = 32; // use # of bytes of SHA-256 output
    static final int PASS_LEN = 32; // use # of bytes of SHA-256 output
    static final int PHONE_LEN = 10; // use # of bytes of SHA-256 output
    static final String HOSTNAME = "localhost";
    static final long TWO_FACTOR_TIMEOUT = 10000000000L; // nano second

    protected SSLSocket socket;
    protected String username; // user associated with this account
    protected boolean timed_out = false; // TODO think about this later...
    protected Hashtable<String, Pair<String, String>> user_table;
    protected Hashtable<String, ArrayList<String>> acl_table; //for the ACL table
    protected Hashtable<String, Pair<String, String>> shared_table; //for shared credentials
    /* pubkey_table: key = Passherd username; value = list of (service name, pub key)*/
    protected Hashtable<String, ArrayList<Pair<String, String>>> pubkey_table; 
    protected MessageDigest messageDigest;
    protected String curr_dir;
    protected PrintWriter audit_writer;
    protected BufferedReader audit_reader;
    protected Pair<String, Long> two_step_code;
    protected boolean verified_password = false;

    public ServerConnection(SSLSocket s) {
        this.socket = s;
        messageDigest = null;
        curr_dir = "";
    }

    class Triple<T1, T2, T3> {
        private T1 first;
        private T2 second;
        private T3 third;

        public T1 first() {
            return first;
        }

        public T2 second() {
            return second;
        }

        public T3 third() {
            return third;
        }

        public Triple(T1 f, T2 s, T3 t) {
            first = f;
            second = s;
            third = t;
        }
    }

    public void run() {
        try {
            // writer,reader for comm with client
            BufferedWriter w = new BufferedWriter(
                                  new OutputStreamWriter(socket.getOutputStream()));
            JSONWriter js;
            BufferedReader r = new BufferedReader(
                                  new InputStreamReader(socket.getInputStream()));
            String m, command;
            JSONObject req; String authName;
            String authPass;
            Response resp;
            while (true) {
                while ((m = r.readLine()) != null) {
                    js = new JSONWriter(w);
                    req = new JSONObject(m);
                    try {
                        command = req.getString("command");
                        // check for authenticated user
                        System.out.println("ServerConnection: command="
                        +command);
                        if (username != null) {
                            switch (command) {
                            case "ATHN":
                            case "LGIN":
                            case "RGST":
                                js.object().key("response").value(Response.DUP_LOGIN).endObject();
                            break;
                            case "ADD":
                                String service = req.getString("service");
                                String sName = req.getString("username");
                                String sPass = req.getString("password");
                                js.object()
                                    .key("response")
                                    .value(addCredential(service, sName, sPass).name()).endObject();
                        
                                break;
                            case "SHARE":
                                String usr = req.getString("user");
                                String service_name = req.getString("service");
                                String shared_user = req.getString("service_user");
                                String shared_pass = req.getString("service_pass");
                                String key = req.getString("public_key");
                                js.object()
                                    .key("response")
                                    .value(shareNewCredentials(usr, service_name, key, shared_user, shared_pass).name()).endObject();
                                break;
                            case "REVOKE":
                                String revoke_usr = req.getString("revoked_user");
                                String revoke_service = req.getString("revoked_service");
                                js.object()
                                    .key("response")
                                    .value(revokeShared(revoke_usr, revoke_service).name()).endObject();
                                break;
                            case "GET1":
                                ArrayList<String> creds;
                                Pair<Response, ArrayList<String>> pair = retrieveCredentials();
                                resp = pair.first();
                                creds = pair.second();
                                js.object().key("response").value(resp.name());
                                if (resp == Response.SUCCESS) {
                                    js.key("data").object().key("credentials")
                                        .array();

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
                                if (resp == Response.SUCCESS) {
                                    js.object().key("response").value(resp.name())
                                        .key("username")
                                        .value(cred.second().first())
                                        .key("password")
                                        .value(cred.second().second())
                                        .endObject();
                                } else {
                                    js.object().key("response").value(resp.name())
                                        .key("username").value("")
                                        .key("password").value("").endObject();
                                }
                                break;

                            case "GETSHARED1":
                                ArrayList<Pair<String,String>> shared_creds;
                                Pair<Response, ArrayList<Pair<String,String>>> temp=  retrieveSharedCredentials();
                                resp = temp.first();
                                shared_creds = temp.second();

                                //TODO: json
                                js.object().key("response").value(resp.name());
                                if (resp == Response.SUCCESS) {
                                    js.key("data").object().key("credentials")
                                       .array();

                                    for (Pair<String, String> s : shared_creds){
                                        js.object()
                                            .key("owner").value(s.first())
                                            .key("service").value(s.second())
                                            .endObject();
                                    }

                                    js.endArray();
                                    js.endObject();
                                }
                                js.endObject();
                                break;
 
                            case "GETSHARED2":
                                Pair<Response, Triple<String, String, String>> temp2;
                                String service2 = req.getString("service");
                                String owner2   = req.getString("owner");
                                temp2 = getSharedPassword(owner2, service2);
                                resp = temp2.first();
                                //Triple(username, password, pubkey) 
                                Triple<String, String, String> result = temp2.second();

                                //json: TODO
                                if (resp == Response.SUCCESS) {
                                    js.object().key("response").value(resp.name())
                                        .key("username")
                                        .value(result.first())
                                        .key("password")
                                        .value(result.second())
                                        .key("public_key")
                                        .value(result.third())
                                        .endObject();
                                } else {
                                    js.object().key("response").value(resp.name())
                                        .key("username").value("")
                                        .key("password").value("")
                                        .key("public_key").value("")
                                        .endObject();
                                }
                                break;
                            case "GET_TRANS":
                                if (!Server.shared_user_table.containsKey(username)){
                                    js.object().key("response").value(Response.FAIL.name())
                                        .endObject();
                                } else {
                                  System.out.println("Getting transactions...");
                                  ArrayList<String> pub_keys = new ArrayList<String>();
                                  if (Server.transaction_table.containsKey(username)){
                                    for (Triple<String,String,String> e : Server.transaction_table.get(username)){
                                      pub_keys.add(e.third());
                                    }
                                  }
                                  js.object().key("response").value(Response.SUCCESS.name())
                                        .key("pub_keys").value(new JSONArray(pub_keys.toArray()))
                                      .endObject();
                                  w.newLine();
                                  w.flush();
                                  System.out.println("Server sent the transactions...");
                                  req = new JSONObject(r.readLine());
                                  JSONArray pub_keys_encrypted = req.getJSONArray("pub_keys");
                                  for (int i = 0; i < pub_keys_encrypted.length(); i++) {
                                      Triple<String,String,String> entry = Server.transaction_table.get(username).get(i);
                                      String pubkey = pub_keys_encrypted.getString(i);
                                      if (pubkey_table.containsKey(entry.first())){
                                        pubkey_table.get(entry.first()).add(new Pair<String,String>(entry.second(),pubkey));
                                      } else {
                                        ArrayList<Pair<String,String>> new_keys = new ArrayList<Pair<String,String>>();
                                        new_keys.add(new Pair<String,String>(entry.second(), pubkey));
                                        pubkey_table.put(entry.first(), new_keys);
                                      }
                                  }
                                  Server.transaction_table.remove(username);
                                  System.out.println("Server finished updating the pub key table");
                                  js = new JSONWriter(w);
                                  js.object().key("response").value(Response.SUCCESS.name())
                                      .endObject();
                                }
                                break;
                            case "DEL":
                                String password = req.getString("password");
                                resp = deleteAccount(password);

                                js.object().key("response").value(resp.name())
                                    .endObject();

                                break;

                            case "CHNG":
                                String oldPass = req.getString("oldPassword");
                                String newPass = req.getString("newPassword");
                                resp = changeAccountPassword(oldPass, newPass);

                                js.object().key("response").value(resp.name())
                                    .endObject();
                                break;

                            case "REMV":
                                service = req.getString("service");
                                resp = deleteCredential(service);
                                js.object().key("response").value(resp.name())
                                    .endObject();
                                break;

                            case "EDIT":
                                service = req.getString("service");
                                sName = req.getString("username");
                                sPass = req.getString("password");
                                resp = updateCredential(service, sName, sPass);

                                js.object().key("response").value(resp.name())
                                    .endObject();

                                break;

                            case "LOGOUT":
                                resp = logout();
                                js.object().key("response").value(resp.name())
                                    .endObject();
                                break;

                            case "CLOSE":
                                // resp = logout();
                                // js.object().key("response").value(resp.name())
                                //     .endObject();

                                js.object().key("response").value("SUCCESS")
                                    .endObject();

                                //if (resp == Response.SUCCESS) {
                                    w.newLine();
                                    w.flush();
                                    socket.close();
                                    return;
                                //}

                            default:
                                // System.out.println("username is not null: command is "+command);
                                // TODO: this is a stub to prevent json from
                                // breaking
                                js.object().key("response").value("NAUTH")
                                    .endObject();
                            }

                            w.newLine();
                            w.flush();

                        } else { // only allow registration or authentication
                            switch (command) {
                            case "LGIN":
                                authName = req.getString("username");
                                authPass = req.getString("password");
                                resp = verifyPassword(authName, authPass);

                                js.object().key("response").value(resp.name())
                                    .endObject();
                                break;
                            case "ATHN":
                                authName = req.getString("username");
                                authPass = req.getString("password");
                                String code = req.getString("code");
                                resp = authAccount(authName, authPass, code);
                                js.object().key("response").value(resp.name())
                                    .endObject();
                                break;

                            case "RGST":
                                String regName = req.getString("username");
                                String regPass = req.getString("password");
                                String carrier = req.getString("carrier");
                                String phone = req.getString("phone");
                                resp = createAccount(regName, regPass, phone,
                                                     carrier);

                                js.object().key("response").value(resp.name())
                                    .endObject();

                                break;
                            case "CLOSE":
                                logout();
                                js.object().key("response").value("SUCCESS")
                                    .endObject();
                                break;
                            default:
                                js.object().key("response").value("NAUTH")
                                    .endObject();
                            }
                            w.newLine();
                            w.flush();
                        }
                    } catch (JSONException je){
                        je.printStackTrace(); //catch, then move on...
                        js.object().key("response").value("BAD_FORMAT").endObject();//send fail to client
                        w.newLine();
                        w.flush();
                    }
                }
                if (timed_out){
                    break;
                }
            }
            //exit loop for whatever reason (timeout break etc.)
            // write back to file, then remove reference to the hash table etc.
            if (username != null && user_table != null){
                logout();
            }
            user_table = null;
            pubkey_table = null;
            username = null;
            log(username, "Logout", Response.SUCCESS);
            r.close();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
     * Helper fxn for simple string input checking
     */
    protected boolean checkInput(String inputs[]) {
        for (String s : inputs) {
            if (s == null || s.isEmpty()) // disallow directory
                return false;
        }
        return true;
    }
    
    /*
     * Returns true if a string is alphanumeric
     */
    public boolean isAlphaNumeric(String s){
    String pattern= "^[a-zA-Z0-9]*$";
        if(s.matches(pattern)){
            return true;
        }
        return false;   
    }

    /*
     * Helper fxn for checking valid usernames
     */
    protected boolean checkUsernameFormat(String usr) {
        return !(usr.contains("/") || usr.contains("\\") || usr.contains(".."));
    }

    /*
     * helper fxn for checking data format to not contain tab spaces
     */
    protected boolean checkDataFormat(String data[]) {
        for (String d : data) {
            if (d.isEmpty() || d.contains("\t")) // disallow directory
                return false;
        }
        return true;
    }

    /*
     * Helper function for salting and hashing master passwords
     */
    protected byte[] saltAndHash(String password, byte salt[])
        throws NoSuchAlgorithmException {
        byte[] toHash = new byte[SALT_LEN + password.length()];

        System.arraycopy(password.getBytes(), 0, toHash, 0, password.length());
        System.arraycopy(salt, 0, toHash, password.length(), SALT_LEN);

        // Hash the master password
        // MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        if (messageDigest == null) {
            messageDigest = MessageDigest.getInstance("SHA-256");
        }
        messageDigest.update(toHash);

        return messageDigest.digest();
    }

    /*
     * Helper function for logging for a specific user Should be used for
     * everything associated with the user
     */
    protected void log(String user, String method_name, Response res) {
        try {
            String logLine;

            if (user == null)
                user = "N/A";
            
            Date date = new Date();

            String ip_addr = socket == null
                || socket.getRemoteSocketAddress() == null ? "N/A" : socket
                .getRemoteSocketAddress().toString();
            
            logLine = date.toString() + "\t" + user + "\t" + ip_addr + "\t"
                + method_name + "\t" + res.name();
            
            Server.logLock.lock();
            Server.logLines.add(logLine);

            /* Notify that there is a new line to consume! */
            Server.logCondition.signal();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            Server.logLock.unlock();
        }
    }

    /*
     * Create new account on server Randomly generates a salt and stores a
     * hashed master password. Assumes: username and password are not null
     * Assumes: username and password are valid (we haven't defined valid yet)
     */
    protected Response createAccount(String new_usr, String password,
                                     String phone, String carrier) {
        if (!checkInput(new String[] { new_usr, password }) ) {
            return Response.WRONG_INPT;
        }
        if (!this.checkUsernameFormat(new_usr)
            || !(phone.matches("[0-9]+") && phone.length() == 10)
            || !(carrier.matches("[0-9]+") && Integer.parseInt(carrier) >= 0 && Integer.parseInt(carrier) <= 2) ) {
            return Response.BAD_FORMAT;
        }
        // Directory already exists
        // Note: Not thread-safe
        if (new File("users/" + new_usr).isDirectory()) {
            // logCenter(username ,"Create Account", Response.FAIL);
            return Response.USER_EXISTS;
        }
        // Create a new directory
        curr_dir = "users/" + new_usr;
        new File(curr_dir).mkdirs();

        // Generate a salt randomly and append it to master password.
        // Salt = 32 bytes since we use SHA-256
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt); // get bytes for salt
        byte[] hashedpassword;
        try {
            shared_table = new Hashtable<String, Pair<String,String>>();
            acl_table = new Hashtable<String, ArrayList<String>>();
            Server.shared_user_table.put(new_usr, new Pair (acl_table, shared_table));  //own creds shared with others
            hashedpassword = saltAndHash(password, salt);

            FileOutputStream writer = new FileOutputStream(curr_dir.concat("/master.txt"));
            writer.write(hashedpassword);
            writer.write(salt);
            writer.write(phone.getBytes("UTF-8"));
            writer.write(carrier.getBytes("UTF-8"));
            writer.flush();
            writer.close();

            /* Create authentication key for logging. */
            PrintWriter keyWriter = new PrintWriter(curr_dir.concat("/key.conf"));

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey authKey = keyGen.generateKey();

            byte[] keyBytes = authKey.getEncoded();
            keyWriter.println(DatatypeConverter.printBase64Binary(keyBytes));
            keyWriter.flush();
            keyWriter.close();

            /* create new file for credentials */
            PrintWriter creds_writer = new PrintWriter(
                                                       curr_dir.concat("/stored_credentials.txt"), "UTF-8");
            creds_writer.close();

            /* create new file for shared creds*/
            PrintWriter shared_creds_writer = new PrintWriter(
                                                       curr_dir.concat("/shared_credentials.txt"), "UTF-8");
            shared_creds_writer.close();

            /* create new file for acl*/
            PrintWriter acl_writer = new PrintWriter(
                                                       curr_dir.concat("/acl.txt"), "UTF-8");
            acl_writer.close();

            /* create new file for public keys for credentials shared with me*/
            PrintWriter pubkey_writer = new PrintWriter(
                                                       curr_dir.concat("/pubkey.txt"), "UTF-8");
            pubkey_writer.close();

            /* create new file for logs */
            PrintWriter logger = new PrintWriter(
                                                 curr_dir.concat("/user_log.txt"), "UTF-8");
            logger.close();
        } catch (Exception e) {
            e.printStackTrace();
            return Response.FAIL;
        }
        /*
        user_table = new Hashtable<String, Pair<String, String>>();
        shared_table = new Hashtable<String, Triple<String, String, String>>();
        */

        /* set the session to be logged in successfully */
        // username = new_usr; //don't do this actually

        // Logging
        log(username, "Create Account", Response.SUCCESS);

        return Response.SUCCESS;
    }

    /*
     * Change password for this user
     */
    protected Response changeAccountPassword(String old_password,
                                             String new_password) {

        byte[] phone;
        char carrier;
        
        if (!checkInput(new String[] { old_password, new_password })) {
            log(username, "Change Account Password", Response.WRONG_INPT);
            return Response.WRONG_INPT;
        }
        if (this.verifyPassword(this.username, old_password) != Response.SUCCESS) {
            // Logging
            System.out.println("Failed to verify password!");
            log(username, "Change Account Password", Response.FAIL);
            return Response.FAIL;
        }

        try {
            FileInputStream f = new FileInputStream(curr_dir.concat("/master.txt"));
            phone = new byte[PHONE_LEN + 1];
            f.skip(PASS_LEN + SALT_LEN);
            f.read(phone, 0, PHONE_LEN + 1);
        } catch (IOException e) {
            e.printStackTrace();
            return Response.FAIL;
        }

        // Generate a salt randomly and append it to master password.
        // Salt = 32 bytes since we use SHA-256
        byte[] salt = new SecureRandom().generateSeed(SALT_LEN);
        byte[] hashedpassword;
        try {
            hashedpassword = saltAndHash(new_password, salt);
        } catch (NoSuchAlgorithmException e) {
            log(username, "Change Account Password", Response.FAIL);
            return Response.FAIL; // should never happen
        }

        // Write hashed master password and the salt to a file named
        // "master.txt"
        // Note: will overwrite the old file
        FileOutputStream writer;
        try {
            writer = new FileOutputStream(curr_dir.concat("/master.txt"));
            writer.write(hashedpassword);
            writer.write(salt);
            writer.write(phone);
            writer.flush();
            writer.close();
        } catch (IOException e1) {
            e1.printStackTrace();
            log(username, "Change Account Password", Response.FAIL);
            return Response.FAIL; // should never happen
        }
        log(username, "Change Account Password", Response.SUCCESS);
        return Response.SUCCESS;
    }

    /*
     * Delete this account and log out the user.
     */
    protected Response deleteAccount(String password) {
        if (!checkInput(new String[] { password })) {
            return Response.WRONG_INPT;
        }
        Response r = this.verifyPassword(this.username, password);
        if (r != Response.SUCCESS) {
            // Logging
            log(this.username, "Delete Account", r);
            return r;
        }

        // Note: guaranteed that this account exists
        // Delete the account

        // Remove myself from the global table
        Server.transaction_lock.lock();
        try{
            //remove myself from the global table
            Server.transaction_table.remove(username);

        }finally{
            Server.transaction_lock.unlock();
        }


        File directory = new File(curr_dir);
        String[] entries = directory.list();
        if (entries != null) {
            // Delete all the files in this directory
            for (String s : entries) {
                File currentFile = new File(directory.getPath(), s);
                currentFile.delete();
            }
        }

        // delete the directory
        directory.delete();

        // Logging
        log(this.username, "Delete Account", Response.SUCCESS);
        username = null;
        shared_table = null;
        acl_table = null;
        user_table = null;

        return Response.SUCCESS;
    }

    /**
     * 
     * @param phoneNumber
     *            the phone number to send the code to
     * @return the code which the user is expected to input, or -1 on error
     */
    protected static int sendSmsCode(String phoneNumber, Carrier c) {
        final String username = "passherd133t@gmail.com";
        final String password = "3lit3haxors";

        String at;
        byte code[] = new byte[4];
        int intCode;
        switch (c) {
        case VERIZON:
            at = "@vtext.com";
            break;
        case SPRINT:
            at = "@messaging.sprintpcs.com";
            break;
        case ATT:
            at = "@txt.att.net";
            break;
        default:
            System.out.println("unrecognized gateway");
            return -1;
        }
        new SecureRandom().nextBytes(code);
        intCode = Math.abs(code[0]) + 4 * Math.abs(code[1]) + 16
            * Math.abs(code[2]) + 64 * Math.abs(code[3]);
        // Assuming you are sending email from localhost
        String host = "localhost";
        String from = "mjv58@cornell.edu";
        // Get system properties
        Properties props = System.getProperties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.imap.ssl.checkserveridentity", "true");

        Session session = Session.getInstance(props,
                                              new javax.mail.Authenticator() {
                                                  protected PasswordAuthentication getPasswordAuthentication() {
                                                      return new PasswordAuthentication(username, password);
                                                  }
                                              });

        try {
            // Create a default MimeMessage object.
            MimeMessage message = new MimeMessage(session);

            // Set From: header field of the header.
            message.setFrom(new InternetAddress(username));

            // Set To: header field of the header.
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(phoneNumber + at));

            // Set Subject: header field
            message.setSubject("Your verification code");

            // Now set the actual message
            message.setText(Integer.toString(intCode));

            // Send message
            Transport.send(message);
        } catch (MessagingException mex) {
            mex.printStackTrace();
            return -1;
        }

        return intCode;
    }


    protected Response verifyPassword(String auth_usr, String password) {
        if (!checkInput(new String[] { auth_usr, password })) {
            return Response.WRONG_INPT;
        }
        if (!this.checkUsernameFormat(auth_usr)) {
            return Response.BAD_FORMAT;
        }
        // Note: Not thread-safe
        if (!(new File("users/" + auth_usr).isDirectory())) {
            // Logging
            log(auth_usr, "Authenticate Account", Response.WRONG_INPT);
            return Response.WRONG_INPT;
        }

        byte salt[] = new byte[SALT_LEN];
        byte stored_pass[] = new byte[PASS_LEN];
        FileInputStream reader;
        try {
            reader = new FileInputStream(
                                         ("users/" + auth_usr).concat("/master.txt"));
            reader.read(stored_pass, 0, PASS_LEN);
            reader.read(salt, 0, SALT_LEN);
            reader.close();

            byte[] hashedpassword = saltAndHash(password, salt);
            if (!Arrays.equals(hashedpassword, stored_pass)) {
                // Logging
                log(auth_usr, "Authenticate Account", Response.WRONG_INPT);
                return Response.WRONG_INPT;
            }
        } catch (IOException e2) {
            e2.printStackTrace();
            log(auth_usr, "Authenticate Account", Response.FAIL);
            return Response.FAIL;
        } catch (NoSuchAlgorithmException e1) { // should never happen
            e1.printStackTrace();
            log(auth_usr, "Authenticate Account", Response.FAIL);
            return Response.FAIL;
        }
        // password is now verified, send the SMS message
        try {
            /*
              The below is purely for testing purposes ONLY
            */
            int test = 0; // hold the carrier info
            try {
                FileInputStream rdr = new FileInputStream(("test.txt"));
                test = rdr.read() - '0'; // use this later
            } catch (IOException e) {
                e.printStackTrace();
                return Response.FAIL;
            }
            if (test == 1){
                verified_password = true;
                authAccount(auth_usr, password, "0000");
            }
            /*End of Test purpose code*/
            if (username == null){
              byte phone[] = new byte[PHONE_LEN]; // phone number
              int carrier; // hold the carrier info
              FileInputStream phone_reader = new FileInputStream(("users/" + auth_usr).concat("/master.txt"));
              phone_reader.skip(PASS_LEN + SALT_LEN);
              phone_reader.read(phone, 0, PHONE_LEN);
              carrier = phone_reader.read() - '0'; // use this later
              two_step_code = new Pair<String, Long>(Integer.toString(sendSmsCode(new String(phone),
                                            Carrier.values()[carrier])), new Long(System.nanoTime())); 
                                                           // TODO: change ATT to user's carrier
              //System.out.println(two_step_code.first());
              //System.out.println(two_step_code.second());


            }
        } catch (IOException e) {
            e.printStackTrace();
            log(auth_usr, "Authenticate Account", Response.FAIL);
            return Response.FAIL;
        }
        verified_password = true;
        
        return Response.SUCCESS;
    }

    /*
     * Authenticate user to system
     */
    protected Response authAccount(String auth_usr, String password, String code) {
        Long elapsed_time = System.nanoTime() - two_step_code.second();
        System.out.println(elapsed_time);
        if (username != null) {// already logged in
            return Response.LOGGED_IN;
        }
        if (!verified_password) {
            return Response.FAIL;
        }

        /*
          The below is purely for testing purposes ONLY
        */
        int test = 0; // hold the carrier info
        try {
            FileInputStream rdr = new FileInputStream(("test.txt"));
            test = rdr.read() - '0'; // use this later
        } catch (IOException e) {
            e.printStackTrace();
            return Response.FAIL;
        }
        /*End of Test purpose code*/

        if (test == 0){ //if this is not a testing instance
            // this should be the second step in two step verification
            if (!this.two_step_code.first().equals(code) || elapsed_time > TWO_FACTOR_TIMEOUT) {
                return Response.BAD_CODE;
            }
        }

        try {
            // init hashtable
            username = auth_usr;
            user_table   = new Hashtable<String, Pair<String, String>>();    //own creds
            pubkey_table = new Hashtable<String, ArrayList<Pair<String, String>>>();//others' creds shared with me
            shared_table = Server.shared_user_table.get(username).second();  //own creds shared with others
            acl_table    = Server.shared_user_table.get(username).first();   //ACL


            curr_dir = "users/" + auth_usr;
            // load user_table with user's credentials
            BufferedReader cred_reader = new BufferedReader(new FileReader(
                                                                           curr_dir.concat("/stored_credentials.txt")));
            String line;
            while ((line = cred_reader.readLine()) != null) {
                String[] curr_cred = line.split("\t");

                if (curr_cred.length != 3) {
                    cred_reader.close();
                    log(username, "Authenticate Account", Response.FAIL);
                    return Response.FAIL;
                }
                // System.out.println("Loaded creds for " + curr_cred[0]);
                user_table.put(curr_cred[0],
                               new Pair<String, String>(curr_cred[1],
                                                        curr_cred[2]));
            }
            cred_reader.close();


            // Load pubkey_table 
            BufferedReader pubkey_reader = new BufferedReader(new FileReader(
                                                                           curr_dir.concat("/pubkey.txt")));
            while ((line = pubkey_reader.readLine()) != null) {
                String[] curr_pubkey = line.split("\t");

                //list of (servicename, public key for decryption)
                ArrayList<Pair<String, String>> pubkey_list = new ArrayList<Pair<String, String>>();
                for (int i = 1; i < curr_pubkey.length; i+=2){
                  pubkey_list.add(new Pair<String, String>(curr_pubkey[i], curr_pubkey[i+1]));
                }
                pubkey_table.put(curr_pubkey[0], pubkey_list);
            }
            pubkey_reader.close();

            // update pubkey_table
            receivePubKey();

            // Logging
            log(auth_usr, "Authenticate Account", Response.SUCCESS);
            return Response.SUCCESS;

        } catch (IOException e2) {
            e2.printStackTrace();
            log(auth_usr, "Authenticate Account", Response.FAIL);
            return Response.FAIL;
        }
    }

    /* 
     * Receive public key for shared credentials and update pubkey_table.
     * Called when user authenticates and attempts to retrieve credentials 
     */
    protected void receivePubKey(){
        // ArrayList of (Passherd username (owner of cred), service name, public key)
        ArrayList<Triple<String,String,String>> transactions;

        //1. look up transaction table by username
        if (Server.transaction_table.contains(username)){

            Server.transaction_lock.lock();
            try{
                // 2. Get the list of pending transactions
                transactions = Server.transaction_table.get(username);

                // 3. Process each transaction, update the pubkey_table
                for (Triple<String,String,String> tr : transactions) {
                    String owner      = tr.first();
                    String servicename = tr.second();
                    String pubkey      = tr.third();

                    if (!pubkey_table.contains(owner)){
                        pubkey_table.put(owner, new ArrayList<Pair<String, String>>());
                    }
                    
                    // note: doesn't check for duplicates but shouldn't matter since pubkey is deterministic
                    pubkey_table.get(owner).add(new Pair(servicename, pubkey)); 
                }
                // 4. Delete the entry from transaction_table
                Server.transaction_table.remove(username);
            
            }finally {
                Server.transaction_lock.unlock();
            }
        }
    }

    /*
     * Returns a list of services for which credentials stored on server.
     */
    protected Pair<Response, ArrayList<String>> retrieveCredentials() {
        
        ArrayList<String> cred_list = new ArrayList<String>();
        for (String k : user_table.keySet()) {
            cred_list.add(k);
        }
        log(username, "Get Credential List", Response.SUCCESS);
        return new Pair<Response, ArrayList<String>>(Response.SUCCESS,
                                                     cred_list);
    }
    
    /*
     * Returns a list of (username, shared services) for which credentials stored on server.
     */
    protected Pair<Response, ArrayList<Pair<String,String>>> retrieveSharedCredentials() {

        ArrayList<Pair<String,String>> cred_list = new ArrayList<Pair<String,String>>(); 
        for (String owner : pubkey_table.keySet()) {
            // Check ACL to see if access is allowed
            Pair<Hashtable<String,ArrayList<String>>, Hashtable<String, Pair<String,String>>> pair 
                    = Server.shared_user_table.get(owner);
            Hashtable<String, ArrayList<String>> owners_acl_table = pair.first();

            if (owners_acl_table.containsKey(username)){ 
                ArrayList<String> shared_creds = owners_acl_table.get(username);

                for (Pair<String, String> shared_info : pubkey_table.get(owner)){
                    if (shared_creds.contains(shared_info.first())){
                        cred_list.add(new Pair(owner, shared_info.first()));
                    }
                }
            }        
        }

        log(username, "Get Credential List", Response.SUCCESS);
        return new Pair<Response, ArrayList<Pair<String,String>>>(Response.SUCCESS,
                                                     cred_list);
    }

    /*
     * Get password for specific service
     */
    protected Pair<Response, Pair<String, String>> getPassword(
                                                               String service_name) {
        if (!checkInput(new String[] { service_name })) {
            return new Pair<Response, Pair<String, String>>(
                                                            Response.WRONG_INPT, null);
        }
        if (!this.checkDataFormat(new String[] { service_name })) {
            return new Pair<Response, Pair<String, String>>(
                                                            Response.BAD_FORMAT, null);
        }
        if (!user_table.containsKey(service_name)) { // credentials not listed
            // in server
            log(username, "Get Credential", Response.NO_SVC);
            return new Pair<Response, Pair<String, String>>(
                                                            Response.NO_SVC, null);
        }
        log(username, "Get Credential", Response.SUCCESS);
        return new Pair<Response, Pair<String, String>>(
                                                        Response.SUCCESS, user_table.get(service_name));
    }
    
    /*
     * Get password for specific shared service
     */
    protected Pair<Response, Triple<String, String, String>> getSharedPassword(
                                                     String owner, String service_name) {
        // 0. Sanity check TODO
        if (!checkInput(new String[] { service_name }) || !checkUsernameFormat(owner)) {
            return new Pair<Response, Triple<String, String, String>>(
                                                            Response.WRONG_INPT, null);
        }
        if (!this.checkDataFormat(new String[] { service_name })) {
            return new Pair<Response, Triple<String, String, String>>(
                                                            Response.BAD_FORMAT, null);
        }

        // 1. Update pubkey_table
        // receivePubKey(); 
        // 2. Get the list of owners who shared credentials with me
        //    Check if owner - service_name is in the pubkey_table.
        if (pubkey_table.containsKey(owner)){ // owner
            for (Pair<String, String> servicename_pubkey : pubkey_table.get(owner)){
                String servicename_candidate = servicename_pubkey.first();
                String pubkey                = servicename_pubkey.second();

                if (service_name.equals(servicename_candidate)){ // service name

                    // 3. Check ACL to see if access is allowed
                    Pair<Hashtable<String,ArrayList<String>>, Hashtable<String, Pair<String,String>>> pair 
                            = Server.shared_user_table.get(owner);
                    Hashtable<String, ArrayList<String>> owners_acl_table = pair.first();

                    if (owners_acl_table.containsKey(username) && owners_acl_table.get(username).contains(service_name)){ 

                        // 4. Get (username, password) from owner's shared_table
                        Hashtable<String, Pair<String, String>> owners_shared_table = pair.second();
                        Pair<String, String> usr_pwd = owners_shared_table.get(service_name);

                        // 5. Return Triple(username, password, pubkey) 
                        Triple<String, String, String> result = new Triple<String, String, String>(usr_pwd.first(), usr_pwd.second(), pubkey);
                        return new Pair<Response, Triple<String, String, String>>(Response.SUCCESS , result);
                    }
                }
            }
        }
        // The user does not have access to this information.
        return new Pair<Response, Triple<String, String, String>>(Response.NO_SVC, null);
    }

    /*
     * Adds new credentials
     */
    protected Response addCredential(String service_name,
                                     String stored_username, String stored_password) {
        if (!checkInput(new String[] { stored_username, stored_password })) {
            log(username, "Add Credential", Response.WRONG_INPT);
            return Response.WRONG_INPT;
        }
        if (!this.checkDataFormat(new String[] { service_name, stored_username,
                                                 stored_password })) {
            log(username, "Add Credential", Response.BAD_FORMAT);
            return Response.BAD_FORMAT;
        }
        if (user_table.containsKey(service_name)) {
            log(username, "Add Credential", Response.CRED_EXISTS);
            return Response.CRED_EXISTS;
        }
        user_table.put(service_name, new Pair<String, String>(
                                                              stored_username, stored_password));

        log(username, "Add Credential", Response.SUCCESS);
        return Response.SUCCESS;
    }

    /*
     * Updates credentials with new password
     */
    protected Response updateCredential(String service_name,
                                        String new_username, String new_stored_pass) {
        if (!checkInput(new String[] { new_username, new_stored_pass })) {

            return Response.WRONG_INPT;
        }
        if (!this.checkDataFormat(new String[] { service_name, new_username,
                                                 new_stored_pass })) {
            log(username, "Update Credential", Response.BAD_FORMAT);
            return Response.BAD_FORMAT;
        }
        if (!user_table.containsKey(service_name)) {
            // System.out.println("Service " + service_name + " not in table.");
            log(username, "Update Credential", Response.NO_SVC);
            return Response.NO_SVC;
        }
        user_table.put(service_name, new Pair<String, String>(
                                                              new_username, new_stored_pass));
        log(username, "Update Credential", Response.SUCCESS);
        return Response.SUCCESS;
    }

    /*
     * Deletes specific credential for specified service
     */
    protected Response deleteCredential(String service_name) {
        if (!checkInput(new String[] { service_name })) {
            log(username, "Delete Credential", Response.WRONG_INPT);
            return Response.WRONG_INPT;
        }
        if (!this.checkDataFormat(new String[] { service_name })) {
            log(username, "Delete Credential", Response.BAD_FORMAT);
            return Response.BAD_FORMAT;
        }
        if (!user_table.containsKey(service_name)) {
            log(username, "Delete Credential", Response.NO_SVC);
            return Response.NO_SVC;
        }
        user_table.remove(service_name);
        log(username, "Delete Credential", Response.SUCCESS);
        return Response.SUCCESS;
    }

    protected Response logout() {
        if (username == null){
            return Response.SUCCESS;
        }
        try {
            /*First write back the stored creds*/
            BufferedWriter writer = new BufferedWriter(new FileWriter(
                                                                      curr_dir.concat("/stored_credentials.txt")));
            for (String k : user_table.keySet()) {
                writer.write(k + "\t" + user_table.get(k).first() + "\t"
                             + user_table.get(k).second() + "\n");
            }
            writer.flush();
            writer.close();

            /*Then write back the shared creds*/
            BufferedWriter shared_writer = new BufferedWriter(new FileWriter(
                                                                      curr_dir.concat("/shared_credentials.txt")));
            for (String k : shared_table.keySet()) {
                shared_writer.write(k + "\t" + shared_table.get(k).first() + "\t"
                             + shared_table.get(k).second() + "\n");
            }
            shared_writer.flush();
            shared_writer.close();

            /*Then write back the pubkeys*/
            BufferedWriter pubkey_writer = new BufferedWriter(new FileWriter(
                                                                      curr_dir.concat("/pubkey.txt")));
            for (String owner : pubkey_table.keySet()) {
                String shared_info = ""; 
                // flattened list of [owner's username, list(servicename, pubkey) ]
                for (Pair<String, String> servicename_pubkey : pubkey_table.get(owner)){
                    shared_info 
                        = shared_info + '\t' + servicename_pubkey.first() + '\t' + servicename_pubkey.second();
                }
                pubkey_writer.write(owner + shared_info + "\n");
            }
            pubkey_writer.flush();
            pubkey_writer.close();

            /*Finally write back the ACL TODO: add another method to get MAC for ACL*/
            BufferedWriter acl_writer = new BufferedWriter(new FileWriter(
                                                                      curr_dir.concat("/acl.txt")));
            /*write all of the service names for each user*/
            for (String k : acl_table.keySet()) {
                acl_writer.write(k);
                for (String service_name : acl_table.get(k)){
                  acl_writer.write("\t" + service_name);
                }
                acl_writer.write("\n");
            }
            acl_writer.flush();
            acl_writer.close();

        } catch (IOException e) {
            e.printStackTrace();
            username = null;
            return Response.FAIL;
        }
        // Also should log here
        log(username, "Logout", Response.SUCCESS);
        username = null;
        return Response.SUCCESS;

    }
    
    /*
    Adds new entry in shared creds file
    Adds entry in ACL for new shared user
    Adds public key to the transaction list
    */
    protected Response shareNewCredentials(String usr, String service_name, String key,
                                            String shared_usr, String shared_pass){
      Server.transaction_lock.lock();
      try {
        //check if the credential exists, and that the user also exists
        if (!user_table.containsKey(service_name)){
          return Response.NO_SVC; //TODO FIX THISSS, check for whether user exists, if user is in the acl, etc.
        }
        if (!Server.shared_user_table.containsKey(usr)){
          return Response.USER_DNE;//
        }
        if (acl_table.contains(usr)){
          if (acl_table.get(usr).contains(service_name)){//it's already shared
            return Response.SUCCESS;
          }
        }
        //add to shared creds
        shared_table.put(service_name, new Pair<String,String>(shared_usr, shared_pass));
        //add to transaction table
        if (Server.transaction_table.containsKey(usr)){
          Server.transaction_table.get(usr).add(new Triple(username, service_name, key));
        } else { //this is a new entry in transaction table
          ArrayList<Triple<String,String,String>> shared_keys = new ArrayList<Triple<String,String,String>>();
          shared_keys.add(new Triple(username,service_name, key));
          Server.transaction_table.put(usr, shared_keys);
        }
        //add new capability to the acl table
        if (acl_table.containsKey(usr)){
          acl_table.get(usr).add(service_name);
        } else {
          ArrayList<String> service_list = new ArrayList<String>();
          service_list.add(service_name);
          acl_table.put(usr, service_list);
        }
      } finally {
        Server.transaction_lock.unlock();
      }
      System.out.println("YAY! I SHARED");
      return Response.SUCCESS;
    }

    /*revokes access by updating the acl table*/
    protected Response revokeShared(String usr, String service_name){
      if (acl_table.contains(usr)){
        ArrayList<String> acl_list = acl_table.get(usr);
        int i = 0;
        while (i < acl_list.size()){
          if (acl_list.get(i).equals(service_name)){
            acl_list.remove(i);
          } else {
            i++;
          }
        }
      }
      return Response.SUCCESS;
    }
}
