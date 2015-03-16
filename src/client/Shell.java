package client;

import server.ServerConnection.Response;
import java.io.Console;
import java.util.List;

public class Shell {
    private static Console con;
    
    public static void run() {
        String command;
        String[] splitCommand;
        boolean loggedIn = true;
        int errno;
        
        con = System.console();
        
        if (con == null)
            return;
        
        while (true) {
            command = con.readLine("PassHerd-0.1a$ ");
            splitCommand = command.split(" ");

            switch (splitCommand[0]) {
            case "login": handleLogin(); break;
            case "register": handleRegister(); break;
            case "add": handleAdd(splitCommand); break;
            case "request": handleReq(splitCommand); break;
            case "delete": handleDel(splitCommand); break;
            case "change": handleChange(splitCommand); break;
            case "exit":
            case "logout": handleLogout(); return;
            case "unregister": handleUnregister(); break;
            case "chpass": handleMasterChange(); break;
            case "help": help(); break;
            default: System.out.println("Command not recognized: " + splitCommand[0]);
            }
        }
    }

    private static void handleUnregister() {
        String conf;
        Response err;
        char[] password;

        conf = con.readLine("Delete account.  Are you sure?[y/n]");

        password = con.readPassword("Password: ");

        if ("y".equals(conf)) {
            err = Client.unregister(password);
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
    }

    private static int handleLogin() {
        String username;
        char[] password;
        Response err;
        
        username = con.readLine("Username: ");

        password = con.readPassword("Password: ");

        err = Client.login(username, password);

        printErr(err);

        return 0;
    }

    private static void handleRegister() {
        String username, email;
        char[] password0, password1;
        Response err;
        boolean samePassword = true;

        username = con.readLine("Username: ");
        password0 = con.readPassword("Password: ");
        password1 = con.readPassword("Verify password: ");

        if (password0.length != password1.length)
            samePassword = false;
        else {
            for (int i = 0; i < password0.length; i++) {
                /* Make sure the user entered the password they intended - twice. */
                samePassword &= (password0[i] == password1[i]);
            }
        }

        if (samePassword) {
            email = con.readLine("Email address: ");
            
            err = Client.register(username, password0, email);
            printErr(err);
        } else {
            System.out.println("Error: passwords do not match.");
        }
    }

    private static void handleAdd(String[] command) {
        String service, username, password;
        Response err;

        if (command.length != 4) {
            System.out.println("Usage: add <service> <username> <password>");
            return;
        }

        service = command[1];
        username = command[2];
        password = command[3];

        err = Client.addCreds(service, username, password);
        printErr(err);
    }

    private static void handleReq(String[] command) {
        String service;
        Response err;

        if (command.length != 2) {
            System.out.println("Usage: request <service | all>");
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
            Pair<Response, String> resp = Client.requestCreds(service);
            String[] creds;
            
            err = resp.first();
            creds = resp.second().split(",");

            if (err == Response.SUCCESS) {
                System.out.println("Credentials for " + service + ":");
                System.out.println("Username: " + creds[0]);
                System.out.println("Password: " + creds[1]);
                return;
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
        
        if (command.length != 4) {
            System.out.println("Usage: change <service> <username> <password>");
            return;
        }

        service = command[1];
        username = command[2];
        password = command[3];

        err = Client.changeCreds(service, username, password);
        printErr(err);
    }

    private static void handleLogout() {
        Response err = Client.logout();
        printErr(err);
    }

    private static void help() {
        
    }

    /* An error decoding and reporting function. */
    private static void printErr(Response resp) {
        switch (resp) {
        case SUCCESS: return;

        case NAUTH:
            System.out.println("Failure: you are not logged in!");
            return;
            
        case WRONG_PASS: /* fall through.  Generic error message in this case. */
        case WRONG_USR:
            System.out.println("Failure: incorrect username or password.");
            return;
            
        case NO_SVC: /* We could not find the requested service stored in the user's account
                      * e.g. Netfilx
                      */
            System.out.println("Failure: the requested service was not found.");
            return;

        case CRED_EXISTS: /* the credential that you tried to add is already in the server */
            System.out.println("Failure: a set of credentials with that name already exists.");
            return;

        case USER_EXISTS: /* could not register an account with that username as one exists */
            System.out.println("Failure: an account with that username already exists.");
            return;
            
        case FAIL: /* Generic error */
            System.out.println("Failure: the system encountered an unknown error.");
            return;
        default: /* For recompilation purposes */
            System.out.println("Failure: unrecognized error code.  Please recompile.");
        }
    }
}
