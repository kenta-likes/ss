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
        
        do {
            command = con.readLine("PassHerd-0.1a$ ");
            splitCommand = command.split(" ");

            switch (splitCommand[0]) {
            case "login": handleLogin(); break;
            case "register": handleRegister(); break;
            case "add": handleAdd(splitCommand); break;
            case "request": handleReq(splitCommand); break;
            case "delete": handleDel(splitCommand); break;
            case "change": handleChange(splitCommand); break;
            case "logout": handleLogout(); break;
            case "help": help(); break;
            default: System.out.println("Command not recognized: " + splitCommand[0]);
            }
            
        } while (loggedIn);

        return;
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

    private static Response handleRegister() {
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
                samePassword &= password0[i] == password1[i];
            }
        }

        if (samePassword) {
            email = con.readLine("Email address: ");
            
            err = Client.register(username, password0, email);
        } else {
            System.out.println("Error: passwords do not match");
            err = Response.FAIL;
        }

        return err;
        
    }

    private static void handleAdd(String[] command) {
        String service, username, password;

        if (command.length != 4) {
            System.out.println("Usage: add <service> <username> <password>");
            return;
        }

        service = command[1];
        username = command[2];
        password = command[3];

        Client.addCreds(service, username, password);
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
            String creds;
            
            err = resp.first();
            creds = resp.second();

            if (err == Response.SUCCESS) {
                System.out.println(creds);
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

    }

    private static void help() {
        
    }

    /* An error decoding function. */
    private static void printErr(Response resp) {
        switch (resp) {
        case SUCCESS: return;
            
        case WRONG_PASS: /* fall through.  Generic error message in this case. */
        case WRONG_USR:
            System.out.println("Failure: incorrect username or password.");
            break;
            
        case NO_SVC: /* We could not find the requested service stored in the user's account
                      * e.g. Netfilx
                      */
            System.out.println("Failure: the requested service was not found.");
            break;
            
        case FAIL: /* Generic error */
            System.out.println("Failure: the system encountered an unknown error.");
            break;
        default: /* For recompilation purposes */
            System.out.println("Failure: unrecognized error code.  Please recompile.");
        }
    }
}
