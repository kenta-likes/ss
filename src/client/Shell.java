package client;

import java.io.Console;

public class Shell {
    //    private Client client;
    private static Console con;
    
    public static void main(String[] args) {
        String command;
        String[] splitCommand;
        boolean loggedIn = true;
        int errno;
        
        con = System.console();
        
        if (con == null)
            return;
        
        /*client = new Client();
          client.connect();*/

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
            default: errno = usage(splitCommand);
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

        //err = client.login(username, password);

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
            err = 0;
            //            err = client.register(username, password0, email);
        } else {
            System.out.println("Error: passwords do not match");
            err = 1;
        }

        return err;
        
    }

    private static int handleAdd(String[] command) {
        int err;
        String service, username, password;

        service = con.readLine("Name of service: ");
        username = con.readLine("Username: ");
        password = con.readLine("Password: ");

        //err = client.addCreds(service, username, password);

        System.out.println("Credentials added.");
        
        return 0;//err;
    }

    private static int handleReq(String[] command) {
        int err;
        return 0;
    }

    private static int handleDel(String[] command) {
        int err;
        String service, confirm;

        service = con.readLine("Name of service: ");
        confirm = con.readLine("Are you sure? [y/n]: ");

        if ("y".equals(confirm)) {
            //err = client.deleteCreds(service);
            System.out.println("Credentials deleted.");
        } else {
            System.out.println("Credentials not deleted.");
            err = 0;
        }

        return 0;//err;
    }

    private static int handleChange(String[] command) {
        int err;
        String service, username, password;

        service = con.readLine("Name of service: ");
        username = con.readLine("New username: ");
        password = con.readLine("New password: ");

        //err = client.changeCreds(service, username, password);

        return 0;//err;
    }

    private static int handleLogout() {
        return -1;
    }

    private static int usage(String[] command) {
        return -1;
    }

    private static void help() {
        
    }
}
