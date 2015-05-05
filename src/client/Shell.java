package client;

import util.*;

import java.io.Console;
import java.util.List;

import password.PasswordClassifier;

public class Shell {
    private static Console con;
    private static String  usr = null;
    
    public static void run() {
        String command;
        String[] splitCommand;
        
        con = System.console();
        
        if (con == null)return;

        System.out.println("Welcome to ...");
        passHerdLogo();
        System.out.println("  - Please type 'register' to create a new account.");
        System.out.println("  - Please type 'login' if you already have an account.");
        System.out.println("  - Please type 'help <command>' for more information");
        

        while (true) {

            if (usr == null){ // Not logged in
                command = con.readLine("PassHerd$ ");
                splitCommand = command.split(" ");
                switch (splitCommand[0]) {
                case "login": handleLogin(); break;
                case "register": handleRegister(); break;
                case "exit": handleExit(); return;
                case "help": if (splitCommand.length == 1) help(); else help(splitCommand[1]);
                    break;
                default: System.out.println("  - Please type 'register' to create a new account.\n  - Please type 'login' if you already have an account.");
                }
            }else{
                command = con.readLine("PassHerd-"+usr+"$ ");
                splitCommand = command.split(" ");

                switch (splitCommand[0]) {
                    // case "login": handleLogin(); break;
                    // case "register": handleRegister(); break;
                case "login":
                case "register": System.out.println("Already logged in."); break;
                case "add": handleAdd(splitCommand); break;
                case "get": handleReq(splitCommand); break;
                case "delete": handleDel(splitCommand); break;
                case "change": handleChange(splitCommand); break;
                case "getshared": handleSharedReq(splitCommand);break;
                case "exit":   handleExit(); return;
                case "logout": handleLogout(); break;
                case "unregister": handleUnregister(); break;
                case "chpass": handleMasterChange(); break;
                case "share": handleShare(splitCommand); break;
                case "update": handleGetTransactions(splitCommand); break;
                case "unshare": handleUnshare(splitCommand); break;
                case "lsshared": handleListShares(); break;
                case "help": if (splitCommand.length == 1) help(); else help(splitCommand[1]);
                    break;
                default: System.out.println("Command not recognized: " + splitCommand[0]);

                }
            }
        }
    }

    private static void passHerdLogo(){
        System.out.println("\n $$$$$$$\\                               $$\\   $$\\                           $$\\ ");
        System.out.println(" $$  __$$\\                              $$ |  $$ |                          $$ |");
        System.out.println(" $$ |  $$ |$$$$$$\\   $$$$$$$\\  $$$$$$$\\ $$ |  $$ | $$$$$$\\   $$$$$$\\   $$$$$$$ |");
        System.out.println(" $$$$$$$  |\\____$$\\ $$  _____|$$  _____|$$$$$$$$ |$$  __$$\\ $$  __$$\\ $$  __$$ |");
        System.out.println(" $$  ____/ $$$$$$$ |\\$$$$$$\\  \\$$$$$$\\  $$  __$$ |$$$$$$$$ |$$ |  \\__|$$ /  $$ |");
        System.out.println(" $$ |     $$  __$$ | \\____$$\\  \\____$$\\ $$ |  $$ |$$   ____|$$ |      $$ |  $$ |");
        System.out.println(" $$ |     \\$$$$$$$ |$$$$$$$  |$$$$$$$  |$$ |  $$ |\\$$$$$$$\\ $$ |      \\$$$$$$$ |");
        System.out.println(" \\__|      \\_______|\\_______/ \\_______/ \\__|  \\__| \\_______|\\__|       \\_______|\n");
    }


    private static void handleGetTransactions(String[] command) {
        Response err;
        if (command.length != 1) {
            System.out.println("Usage: share update");
            return;
        }

        err = Client.getTransactions();
        if (err != Response.SUCCESS)
            printErr(err);

        return;
    }

    private static void handleListShares() {
        Response err;
        Pair<Response, List<Pair<String, List<String>>>> resp;
        
        resp = Client.listShares();
        err = resp.first();
        
        if (err == Response.SUCCESS) {
            List<Pair<String, List<String>>> shares = resp.second();

            for (Pair<String, List<String>> p : shares) {
                System.out.print(p.first() + ": can view ");

                for (String s : p.second())
                    System.out.print(s + " ");

                System.out.println();
            }
        } else {
            printErr(err);
        }
    }

    private static void handleUnshare(String[] command) {
        Response err;

        if (command.length != 3) {
            System.out.println("Usage: unshare <service> <username>");
            return;
        }
        err = Client.unshareCreds(command[1], command[2]);
        printErr(err);
    }

    private static void handleShare(String[] command) {
        char[] password;
        Response err;
        
        if (command.length != 3) {
            System.out.println("Usage: share <service> <username>");
            return;
        }

        password = con.readPassword("Password: ");
        err = Client.shareNewCreds(command[1], command[2], password);

        java.util.Arrays.fill(password, ' ');

        if (err != Response.SUCCESS)
            printErr(err);

        return;
    }

    private static int handleUnregister() {
        String conf;
        Response err;
        char[] password;

        conf = con.readLine("Delete account. Are you sure? [y/n]: ");


        if ("y".equals(conf)) {
            password = con.readPassword("Password: ");
            err = Client.unregister(password);

            /* Clear the password from memory. */
            java.util.Arrays.fill(password, ' ');

            if (err == Response.SUCCESS) usr = null;            
            printErr(err);
        } else {
            System.out.println("Account not deleted.");
        }
        return 0;

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

        if (password0.length != password1.length) {
            System.out.println("Error: passwords do not match.");
            return;
        }

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
    
    private static boolean invalidUsername(String username){
        return username.contains(" ") || username.contains("*") || username.contains("/") || username.contains("\\") || username.contains("..");
    }

    private static String invalidUsernameWarning =
      "Username cannot contain the following characters: <space>, <tab>, *, /, \\, ..\nPlease try again.";

    private static int handleLogin() {
        String username;
        char[] password;
        Response err;
        
        // USERNAME
        username = con.readLine("Username: ");
        while (username.length() == 0 || invalidUsername(username)){
            if (username.length() == 0) System.out.println("Uasername cannot be empty.  Please try again.");
            else {
                System.out.println(invalidUsernameWarning);
            }
            username = con.readLine("Username: ");
        }

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

        if (err == Response.SUCCESS) {
            usr = username;
            passHerdLogo();
            help();
            err = Client.getTransactions(); // CONSUME TRANSACTIONS
        }

        /* Clear the password from memory. */
        java.util.Arrays.fill(password, ' ');

        printErr(err);
        return 0;
    }

    private static void handleRegister() {
        String username, phone, carrier;
        char[] password0 = null, password1 = null;
        Response err;
        boolean strongPassword = false, samePassword = false, validCarrier = false;
        int c, p;
        PasswordClassifier passTest = new PasswordClassifier();

        // USERNAME
        username = con.readLine("Username: ");
        while (username.length() == 0 || invalidUsername(username)){

            if (username.length() == 0) System.out.println("Username cannot be empty.  Please try again.");
            else {
                System.out.println(invalidUsernameWarning);
            }
            username = con.readLine("Username: ");
        }

        // PASSWORD
        password0 = con.readPassword("Password: ");
        strongPassword = passTest.isStrong(new String(password0));
        while (password0.length == 0 || !strongPassword || !samePassword){
            if (password0.length == 0){
                System.out.println("Password cannot be empty.  Please try again.");
                password0 = con.readPassword("Password: ");
                strongPassword = false;
            } else if (!strongPassword){
                System.out.println("That password is too weak! Please use a stronger password.");
                System.out.println("Hint:\n - Make it longer (>10 characters)\n - Include numbers and special characters \n - Avoid common English words");
                password0 = con.readPassword("Password: ");
                strongPassword = passTest.isStrong(new String(password0));
            } 

            // VERIFY PASSWORD
            if (password0.length > 0 && strongPassword){
                password1 = con.readPassword("Verify password: ");
                // compare password
                if (password0.length != password1.length) samePassword = false;
                else {
                    samePassword = true;
                    for (int i = 0; i < password0.length; i++) {
                        samePassword &= (password0[i] == password1[i]);
                    }
                }
                
                // passwords don't match
                if (!samePassword){
                    System.out.println("Passwords do not match. Please try again.");
                    password0 = con.readPassword("Password: ");
                    strongPassword = passTest.isStrong(new String(password0));
                }
            }
            
        }        

        // PHONE NUMBER
        phone = con.readLine("10 digit phone number (e.g. 4081234567): ");
        while (!(phone.matches("[0-9]+") && phone.length() == 10)) {
            if (!(phone.matches("[0-9]+"))){
                phone = con.readLine("Invalid characters. Please try again (e.g. 4081234567): ");
            }else{
                phone = con.readLine("Invalid length. Please try again (e.g. 4081234567): ");
            }	
        }

        // CARRIER
        carrier = con.readLine("Carrier (0 = Verizon, 1 = AT&T, 2 = Sprint): ");
        while (!validCarrier){
            try {
                c = Integer.parseInt(carrier);
                validCarrier = !(c != 0 && c != 1 && c != 2);
            } catch (NumberFormatException e){
                validCarrier = false;
            }
            if (!validCarrier){
                System.out.println("Invalid carrier");
                carrier = con.readLine("Please select again (0 = Verizon, 1 = AT&T, 2 = Sprint): ");
            }         
        }
        
        
        // REQUEST TO SERVER
        err = Client.register(username, password0, phone, carrier);
        if (err == Response.SUCCESS)System.out.println("Account successfully created. Please login.");
        printErr(err);
  
        // CLEAR PASSWORD FROM MEMORY
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

    private static void handleSharedReq(String[] command) {//GETSHARED
        String service;
        Response err;
        Pair<Response, List<Pair<String, String>>> resp = null;
        
        if (command.length != 2 && command.length != 3) {
            System.out.println("Usage: " + command[0] + " shared {all | <service> <username>}");
            return;
        }

        service = command[1];

        err = Client.getTransactions(); // CONSUME TRANSACTIONS
        printErr(err);
            
        if (service.equals("all")) { // getshared all
            resp = Client.requestSharedCreds();
            err = resp.first();

            List<Pair<String, String>> creds = resp.second();

            if (err == Response.SUCCESS) {
                for (Pair<String, String> p : creds)
                    System.out.println(p.first() + ": " + p.second());
            } else {
                printErr(err);
            }

            return;
        } else { // getshared <service> <username>
            if (command.length != 3) {
                System.out.println("Usage: getshared <service> <username>");
                return;
            }
                
            Pair<Response, Pair<String, String>> shared =
                Client.requestOneSharedCred(command[1], command[2]);
            
            Pair<String, String> creds;

            err = shared.first();

            if (err == Response.SUCCESS) {
                creds = shared.second();
                
                System.out.println("Credentials for " +
                                   service + " shared from " + command[2] + ":");
                System.out.println("Username: " + creds.first());
                System.out.println("Password: " + creds.second());

                return;
            } else {
                printErr(err);
            }
        }
    }

    private static void handleReq(String[] command) { // GET
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
        char pass[];
        
        if (command.length != 2) {
            System.out.println("Usage: change <service>");
            return;
        }

        service = command[1];
        username = con.readLine("Username: ");
        password = con.readLine("Password: ");

        pass = con.readPassword("Password: ");
        err = Client.changeCreds(service, username, password, pass);
        printErr(err);
    }

    private static int handleLogout() {
        if (usr != null){
            Response err = Client.logout();
            if (err == Response.SUCCESS) usr = null;
            printErr(err);
        }
        return 0;
    }

    private static int handleExit(){
        handleLogout();
        Response err = Client.exit();
        printErr(err);
        return 0;
    }

    private static void help() {
        if (usr == null){
            System.out.println("  - Please type 'register' to create a new account.");
            System.out.println("  - Please type 'login' if you already have an account.");
            System.out.println("  - Please type 'help <command>' for more information");
        }else{
            System.out.println("=============================================================================");
            System.out.println("All commands: Type help <command> for more information.");
            System.out.println("=============================================================================");
            System.out.println(" * Manage your credentials *");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println("    - add\t\t- get\n    - delete\t\t- change");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println(" * View credentials shared with you *");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println("    - getshared\n");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println(" * Share your credentials *");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println("    - share\t\t- unshare\n    - update\t\t- lsshared");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println(" * Manage your PassHerd account *");
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println("    - chpass\t\t- logout\n    - exit\t\t- unregister");
            System.out.println("-----------------------------------------------------------------------------");
        }       
    }

    

    private static void help(String command) {
        String helpMsg;
        if (usr == null){
            switch (command) {
            case "login": helpMsg = "login: initiates a login prompt.  Enter your username and password to gain access to your stored credentials.";
                break;
            case "register": helpMsg = "register: initiates the creation of a new account.";
                break;
            case "help": helpMsg = "help <command>: display help about a certain command."; break;
            default: helpMsg = "Error: command not recognized.";
            }
        }else{
            switch (command) {
            case "share": helpMsg = "share <service> <username>: share credentials for a service with another user.";
                break;

            case "unshare": helpMsg = "unshare <service> <username>: stop sharing credentials for a service with another user.";
                break;

            case "lsshared": helpMsg = "lsshared: show all shared credentials and with whom they are shared.";
                break;
            case "getshared": helpMsg= "getshared {all | <service> <username>}: displays the names of all shared services, or the username and password associated with a certain service and user.";
                
            case "add": helpMsg = "add <service>: stores the username and password for the service.";
                break;
                    
            case "get": helpMsg = command + " <all | service>: displays the names of all stored services, or the username and password associated with a certain service.";
            break;
                    
            case "delete": helpMsg = "delete <service>: deletes the credentials associated with the service.  Asks for confirmation before deleting.";
                break;
                    
            case "change": helpMsg = "change <service>: changes the username and password associated with the service.";
                break;
                    
            case "exit": helpMsg = command + ": logs you out and exits PassHerd.";
                break;
            case "logout": helpMsg = command + ": logs you out.";
                break;
            case "update": helpMsg = command + ": updates your list of shared credentials.";
                break;
                    
            case "unregister": helpMsg = "unregister: deletes the logged-in account and all stored credentials.  Asks for confirmation before deleting.";
                break;
                    
            case "chpass": helpMsg = "chpass: initiates a change to your account master password.";
                break;
            case "help": helpMsg = "help <command>: display help about a certain command."; break;
            default: helpMsg = "Error: command not recognized.";
            }
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

        case MASTER_EMPTY:
            System.out.println("Error: username and password cannot be empty.");
            return;

        case MASTER_BAD_FORMAT:
            System.out.println("Error: "+invalidUsernameWarning);
            return;


        case CRED_BAD_FORMAT:
            System.out.println("Error: Credential servicename, username and password cannot be empty or contain <tab>.");
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

        case BAD_CODE:
            System.out.println("Error: 2-factor authentication code is incorrect or expired.");
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
        case USER_DNE:
            System.out.println("Error: Username not found");
            return;
        default: /* For recompilation purposes */
            System.out.println("Error: unrecognized error code.  Please recompile.");
        }
    }
}
