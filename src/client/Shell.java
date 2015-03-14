package client;

import java.io.Console;

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
        int err = 0;
        
        username = con.readLine("Username: ");

        password = con.readPassword("Password: ");

        err = Client.login(username, password);

        if (err != 0)
            System.out.println("Error: incorrect username or password.");

        return err;
    }

    private static int handleRegister() {
        String username, email;
        char[] password0, password1;
        int err;
        boolean samePassword = true;

        username = con.readLine("Username: ");
        password0 = con.readPassword("Password: ");
        password1 = con.readPassword("Verify password: ");
        email = con.readLine("Email address: ");

        if (password0.length != password1.length)
            samePassword = false;
        else {
            for (int i = 0; i < password0.length; i++) {
                samePassword &= password0[i] == password1[i];
            }
        }

        if (samePassword) {
            System.out.println("Matching");
            err = Client.register(username, password0, email);
        } else {
            System.out.println("Error: passwords do not match");
            err = 1;
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
    }

    private static void handleDel(String[] command) {
        String service, confirm;

        if (command.length != 2) {
            System.out.println("Usage: delete <service>");
            return;
        }

        service = command[1];

        System.out.println("Deleting credentials for " + service);
        confirm = con.readLine("Are you sure? [y/n]: ");

        if ("y".equals(confirm)) {
            Client.deleteCreds(service);
        } else {
            System.out.println("Credentials not deleted.");
        }
    }

    private static void handleChange(String[] command) {
        String service, username, password;
        if (command.length != 4) {
            System.out.println("Usage: change <service> <username> <password>");
            return;
        }

        service = command[1];
        username = command[2];
        password = command[3];

        Client.changeCreds(service, username, password);
    }

    private static void handleLogout() {

    }

    private static void help() {
        
    }
}
