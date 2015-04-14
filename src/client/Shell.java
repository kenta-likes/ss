package client;

import util.*;
import java.io.Console;
import java.util.List;

public class Shell {
    private static Console con;
    
    public static void run() {
        String command;
        String[] splitCommand;
        
        con = System.console();
        
        if (con == null)
            return;
        
        while (true) {
            command = con.readLine("PassHerd-0.3b$ ");
            splitCommand = command.split(" ");

            switch (splitCommand[0]) {
            case "login": handleLogin(); break;
            case "register": handleRegister(); break;
            case "add": handleAdd(splitCommand); break;
            case "get":
            case "creds": handleReq(splitCommand); break;
            case "delete": handleDel(splitCommand); break;
            case "change": handleChange(splitCommand); break;
            case "exit":
            case "logout": handleLogout(); return;
            case "unregister": handleUnregister(); return;
            case "chpass": handleMasterChange(); break;
            case "help": if (splitCommand.length == 1) help(); else help(splitCommand[1]);
                break;
            default: System.out.println("Command not recognized: " + splitCommand[0]);
            }
        }
    }

    private static void handleUnregister() {
        String conf;
        Response err;
        char[] password;

        conf = con.readLine("Delete account. Are you sure? [y/n]: ");

        password = con.readPassword("Password: ");

        if ("y".equals(conf)) {
            err = Client.unregister(password);

            /* Clear the password from memory. */
            java.util.Arrays.fill(password, ' ');
            
            printErr(err);
        } else {
            System.out.println("Account not deleted.");
        }
    }

    private static void handleMasterChange() {
        char[] oldPassword;
        char[] password0;
        char[] password1;
        boolean samePassword = true;
        Response err;

        oldPassword = con.readPassword("Current password: ");
        password0 = con.readPassword("New password: ");
        password1 = con.readPassword("Retype new password: ");

        for (int i = 0; i < password0.length; i++) {
            /* Make sure the user entered the password they intended - twice. */
            samePassword &= (password0[i] == password1[i]);
        }

        if (!samePassword) {
            System.out.println("Error: passwords do not match.");
            return;
        }

        err = Client.changeMaster(oldPassword, password0);
        
        /* Clear the passwords from memory. */
        java.util.Arrays.fill(oldPassword, ' ');
        java.util.Arrays.fill(password0, ' ');
        java.util.Arrays.fill(password1, ' ');
    }

    private static int handleLogin() {
        String username;
        char[] password;
        Response err;
        
        username = con.readLine("Username: ");

        password = con.readPassword("Password: ");

        err = Client.login(username, password);

        

        printErr(err);
        if (err == Response.SUCCESS)
        	handleAuth(username, password);
        else
        {
        	/* Clear the password from memory. */
            java.util.Arrays.fill(password, ' ');
        }
        return 0;
    }
    
    private static int handleAuth(String username, char[] password) {
        Response err;
        String code = con.readLine("2-factor Authentication Code: ");
        
        err = Client.auth(username, password, code);

        /* Clear the password from memory. */
        java.util.Arrays.fill(password, ' ');

        printErr(err);
        return 0;
    }

    private static void handleRegister() {
        String username, email;
        char[] password0, password1;
        Response err;
        boolean samePassword = true, containsComma = false;

        username = con.readLine("Username: ");
        password0 = con.readPassword("Password: ");
        password1 = con.readPassword("Verify password: ");

        if (password0.length != password1.length)
            samePassword = false;
        else {
            for (int i = 0; i < password0.length; i++) {
                /* Make sure the user entered the password they intended - twice. */
                samePassword &= (password0[i] == password1[i]);

                if (password0[i] == ',')
                    containsComma = true;
            }
        }

        if (samePassword) {
            email = con.readLine("Email address: ");
            
            err = Client.register(username, password0, email);
            printErr(err);
        } else {
            System.out.println("Error: passwords do not match.");
        }

        /* Clear the password from memory. */
        java.util.Arrays.fill(password0, ' ');
        java.util.Arrays.fill(password1, ' ');

    }

    private static void handleAdd(String[] command) {
        String service, username, password;
        Response err;

        if (command.length != 2) {
            System.out.println("Usage: add <service>");
            return;
        }

        service = command[1];
        username = con.readLine("Username: ");
        password = con.readLine("Password: ");

        err = Client.addCreds(service, username, password);
        printErr(err);
    }

    private static void handleReq(String[] command) {
        String service;
        Response err;

        if (command.length != 2) {
            System.out.println("Usage: " + command[0] + " <service | all>");
            return;
        }

        service = command[1];

        if (service.equals("all")) {
            Pair<Response, List<String>> resp = Client.requestAllCreds();
            List<String> creds;
            
            err = resp.first();
            creds = resp.second();

            if (err == Response.SUCCESS) {
                for (String s : creds)
                    System.out.println(s);

                return;
            }            
        } else {
            Pair<Response, Pair<String, char[]>> resp = Client.requestCreds(service);
            Pair<String, char[]> creds;
            char[] pass;
            
            err = resp.first();

            if (resp.second() != null) {
                creds = resp.second();

                if (err == Response.SUCCESS) {
                    System.out.println("Credentials for " + service + ":");
                    System.out.println("Username: " + creds.first());
                    System.out.print("Password: ");
                    
                    pass = creds.second();
                    /* Print and zero out array. */
                    for (int i = 0; i < pass.length; i++) {
                        System.out.print(pass[i]);
                        pass[i] = ' ';
                    }
                        
                    System.out.println();
                    return;
                }
            }
        }

        printErr(err);
    }

    private static void handleDel(String[] command) {
        String service, confirm;
        Response err;

        if (command.length != 2) {
            System.out.println("Usage: delete <service>");
            return;
        }

        service = command[1];

        System.out.println("Deleting credentials for " + service);
        confirm = con.readLine("Are you sure? [y/n]: ");

        if ("y".equals(confirm)) {
            err = Client.deleteCreds(service);
            printErr(err);
        } else {
            System.out.println("Credentials not deleted.");
        }
    }

    private static void handleChange(String[] command) {
        String service, username, password;
        Response err;
        
        if (command.length != 2) {
            System.out.println("Usage: change <service>");
            return;
        }

        service = command[1];
        username = con.readLine("Username: ");
        password = con.readLine("Password: ");

        err = Client.changeCreds(service, username, password);
        printErr(err);
    }

    private static void handleLogout() {
        Response err = Client.logout();
        printErr(err);
    }

    private static void help() {
        System.out.println("All commands: login register add get creds delete change exit logout unregister chpass help.\nType help <command> for more information.");
    }

    private static void help(String command) {
        String helpMsg;
        
        switch (command) {
        case "login": helpMsg = "login: initiates a login prompt.  Enter your username and password to gain access to your stored credentials.";
                break;
            
        case "register": helpMsg = "register: initiates the creation of a new account.";
            break;
            
        case "add": helpMsg = "add <service>: stores the username and password for the service.";
            break;
                
        case "get":
        case "creds": helpMsg = command + " <all | service>: displays the names of all stored services, or the username and password associated with a certain service.";
        break;
                
        case "delete": helpMsg = "delete <service>: deletes the credentials associated with the service.  Asks for confirmation before deleting.";
            break;
                
        case "change": helpMsg = "change <service>: changes the username and password associated with the service.";
            break;
                
        case "exit":
        case "logout": helpMsg = command + ": logs you out and exits PassHerd.";
        break;
                
        case "unregister": helpMsg = "unregister: deletes the logged-in account and all stored credentials.  Asks for confirmation before deleting.";
            break;
                
        case "chpass": helpMsg = "chpass: initiates a change to your account master password.";
            break;
        case "help": helpMsg = "help <command>: display help about a certain command."; break;
        default: helpMsg = "Error: command not recognized.";
        }

        System.out.println(helpMsg);
    }

    /* An error decoding and reporting function. */
    private static void printErr(Response resp) {
        switch (resp) {
        case SUCCESS: return;

        case NAUTH:
            System.out.println("Error: you are not logged in!");
            return;

        case BAD_FORMAT:
            System.out.println("Error: the <tab>, '..', '/', and ''\\'' characters are not allowed.");
            return;
            
        case WRONG_INPT: /* fall through.  Generic error message in this case. */
            System.out.println("Error: incorrect username or password.");
            return;
            
        case NO_SVC: /* We could not find the requested service stored in the user's account
                      * e.g. Netfilx
                      */
            System.out.println("Error: the requested service was not found.");
            return;

        case CRED_EXISTS: /* the credential that you tried to add is already in the server */
            System.out.println("Error: a set of credentials with that name already exists.");
            return;

        case USER_EXISTS: /* could not register an account with that username as one exists */
            System.out.println("Error: an account with that username already exists.");
            return;
            
        case DUP_LOGIN: /* duplicated login attempts */   
        	System.out.println("Error: you are already logged in.");
        	return;
        
        case FAIL: /* Generic error */
            System.out.println("Error: the system encountered an unknown error.");
            return;
        case MAC:
        	System.out.println("Error: Server data integrity appears to be compromised - MAC mismatch detected");
        	return;
        default: /* For recompilation purposes */
            System.out.println("Error: unrecognized error code.  Please recompile.");
        }
    }
}
