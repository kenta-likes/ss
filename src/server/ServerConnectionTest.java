package server;

import util.*;
import static org.junit.Assert.*;

import java.io.File;
import java.util.ArrayList;

import org.junit.Test;


public class ServerConnectionTest {
    /*
     * All of these functions are protected and only called by the server loop. They work with
     * assumptions on input/state that are written under each of the specs.
     * */

	@Test
	public void testLog_Center() {
		ServerConnection sc = new ServerConnection(null);
		//sc.createAccount("cs794", "helloworld");
		sc.logCenter("cs794", "Create Account", Response.SUCCESS);
		sc.logCenter("cs794", "Create Account", Response.FAIL);
		sc.logCenter("cs794", "Create Account", Response.FAIL);
	}

	@Test
	public void testCreateAccount() throws Exception{
    		// Create an account
    	ServerConnection sc = new ServerConnection(null);
    	try{
    		// case0. invalid inputs
    		assertEquals(Response.BAD_FORMAT, sc.createAccount("fo/ o", "helloworld"));
    		
    		// case1. success
    		assertEquals(Response.SUCCESS, sc.createAccount("foo", "helloworld"));
    		
    		// case2. try to create a duplicate account
    		assertEquals(Response.USER_EXISTS, sc.createAccount("foo", "helloworld"));

	    } finally {
	        sc.deleteAccount("helloworld");
	    }
	}

	@Test
	public void testChangeAccountPassword() {
		// 1. Create an account
		ServerConnection sc = new ServerConnection(null);
		
		try{
    		assertEquals(Response.SUCCESS, sc.createAccount("kjd88", "test"));
    		
    		// 2. Change password
    		assertEquals(Response.SUCCESS, sc.changeAccountPassword("test", "test1"));
    		
    		// 3. Authenticate with the old password
    		assertEquals(Response.WRONG_INPT, sc.authAccount("kjd88", "test"));
    		
    		// 4. Authenticate with the new password
    		assertEquals(Response.SUCCESS, sc.authAccount("kjd88", "test1"));
    		
    		// 5. Delete account
    		sc.deleteAccount("test1");
		} finally {
		    sc.deleteAccount("test1");
		}
		
	}

	@Test
	public void testDeleteAccount() {
    	// 1. Create an account
    	ServerConnection sc = new ServerConnection(null);
        try {
    		assertEquals(Response.SUCCESS, sc.createAccount("kl459", "kenta"));
    		
    		// 2. Delete with wrong password
    		assertEquals(Response.WRONG_INPT, sc.deleteAccount("kent"));
    		
    		// 3. Delete with correct password
    		assertEquals(Response.SUCCESS, sc.deleteAccount("kenta"));
	    } finally {
	        sc.deleteAccount("kenta");
	    }
		
	}

	@Test
	public void testAuthAccount() {
		ServerConnection sc = new ServerConnection(null);
		try {
		    //create account
            assertEquals(Response.SUCCESS, sc.createAccount("cs794", "helloworld"));
            //test auth with wrong password, correct username
    		assertEquals(Response.WRONG_INPT, sc.authAccount("cs794", "halloworld"));
    		//test auth with wrong username, correct password
    		assertEquals(Response.WRONG_INPT, sc.authAccount("foobar", "helloworld"));
            //test auth with wrong username, wrong password
            assertEquals(Response.WRONG_INPT, sc.authAccount("foobar", "baz"));
            //test auth with empty login credentials
            assertEquals(Response.WRONG_INPT, sc.authAccount("", ""));
            //test auth with null login credentials
            assertEquals(Response.WRONG_INPT, sc.authAccount(null, null));
    		
    		//test auth with correct login credentials
            assertEquals(Response.SUCCESS, sc.authAccount("cs794", "helloworld"));
		} finally {
		    sc.deleteAccount("helloworld");
		}
	}
/*
	@Test
	public void testRetrieveCredentials() {
		ServerConnection sc = new ServerConnection(null);
		try {
		    //create account
            assertEquals(Response.SUCCESS, sc.createAccount("foo", "test"));
            
            //retrieve 0
            ArrayList<String> cred_list = new ArrayList<String>();
            Pair<Response, ArrayList<String>> expected = new Pair<Response,ArrayList<String>>(Response.SUCCESS, cred_list);
    		assertEquals(expected.second(), sc.retrieveCredentials().second());
    		assertEquals(expected.first(), sc.retrieveCredentials().first());
    		
            
            
            //add another credential
    		assertEquals(Response.SUCCESS, sc.addCredential("Amazon", "cs794@cornell.edu", "helloworld"));
    		cred_list = new ArrayList<String>();
    		cred_list.add("Amazon");
    		
    		//retrieve 1
    		expected = new Pair<Response,ArrayList<String>>(Response.SUCCESS, cred_list);
    		assertEquals(expected.second(), sc.retrieveCredentials().second());
    		assertEquals(expected.first(), sc.retrieveCredentials().first());
    		
    		//add another credential
    		assertEquals(Response.SUCCESS, sc.addCredential("Facebook", "cs794@cornell.edu", "imhungry"));
    		cred_list.add("Facebook");
    		
            //retrieve 2
    		expected = new Pair<Response,ArrayList<String>>(Response.SUCCESS, cred_list);
    		assert(expected.second().contains(sc.retrieveCredentials().second()));
    		assertEquals(expected.first(), sc.retrieveCredentials().first());
    		
    		
		} finally {
		    sc.deleteAccount("test");
		}
	}

	@Test
	public void testGetPassword() {
		ServerConnection sc = new ServerConnection(null);
		try {
		    //create account
            assertEquals(Response.SUCCESS, sc.createAccount("foo", "test"));
            
            //case1. retrieve a credential that does not exist
            Pair<String, String> cred = null;
            Pair<Response, Pair<String, String>> expected = new Pair<Response,Pair<String, String>>(Response.NO_SVC, cred);	
            Pair<Response, Pair<String, String>> result = sc.getPassword("Amazon");
            assertEquals(expected.first(), result.first());
            assertEquals(expected.second(), result.second());
            
            
            //case2. retrieve a credential that exists
            assertEquals(Response.SUCCESS, sc.addCredential("Facebook", "cs794@cornell.edu", "imhungry"));
            cred = new Pair<String, String>("cs794@cornell.edu", "imhungry");
            expected = new Pair<Response, Pair<String, String>>(Response.SUCCESS, cred);
            result = sc.getPassword("Facebook");
            assertEquals(expected.first(), result.first());
            assertEquals(expected.second().first(), result.second().first());
            assertEquals(expected.second().second(), result.second().second());

		}finally {
		    sc.deleteAccount("test");
		}
	}

	@Test
	public void testAddCredential() {
        ServerConnection sc = new ServerConnection(null);
        try {
            //create account Note: this logins the user
            assertEquals(Response.SUCCESS, sc.createAccount("foobar", "baz"));

            //try to add credentials with empty inputs
            assertEquals(Response.WRONG_INPT, sc.addCredential("", "", ""));
            //try to add credentials with null inputs
            assertEquals(Response.WRONG_INPT, sc.addCredential(null, null, null));


            //try to add credentials with tabspaces in service name
            assertEquals(Response.BAD_FORMAT, sc.addCredential("face\tbook", "username", "pass\tword"));
            //try to add credentials with tabspaces in password
            assertEquals(Response.BAD_FORMAT, sc.addCredential("facebook", "username", "pass\tword"));
            //try to add credentials with tabspaces in username
            assertEquals(Response.BAD_FORMAT, sc.addCredential("facebook", "user\tname", "password"));
            //add cred with only tabspace in service name
            assertEquals(Response.BAD_FORMAT, sc.addCredential("\t", "\t", "\t"));

            //Add credentials
            assertEquals(Response.SUCCESS, sc.addCredential("facebook", "foobar", "baz"));
            //Add another credential
            assertEquals(Response.SUCCESS, sc.addCredential("gmail", "foobar2", "baz2"));
            //Add credential with same name
            assertEquals(Response.CRED_EXISTS, sc.addCredential("facebook", "barfoo", "bazfoo"));
            //check stored fb username
            assertEquals("foobar", sc.getPassword("facebook").second().first());
            //check stored gmail username
            assertEquals("foobar2", sc.getPassword("gmail").second().first());
            //check stored facebook pass
            assertEquals("baz", sc.getPassword("facebook").second().second());
            //check stored gmail pass
            assertEquals("baz2", sc.getPassword("gmail").second().second());
            
            
            
        } finally {
            sc.deleteAccount("baz");
        }
	}

	@Test
	public void testUpdateCredential() {
		ServerConnection sc = new ServerConnection(null);
        try {
        	//create account and add a credential Note: this logins the user
            assertEquals(Response.SUCCESS, sc.createAccount("foo", "test"));
            assertEquals(Response.SUCCESS, sc.addCredential("Cornell", "kenta", "iamkent"));
            
            // case1. Update attempt on a credential that does not exist
            assertEquals(Response.NO_SVC, sc.updateCredential("Harvard", "kenta", "iamkenta"));
            
            // case2. Successfully updates a credential
            assertEquals(Response.SUCCESS, sc.updateCredential("Cornell", "kenta", "iamkenta"));
            
            // case3. Invalid password
            assertEquals(Response.BAD_FORMAT, sc.updateCredential("Cornell", "../chie", "iam 	kenta"));
            
        	
        } finally {
            sc.deleteAccount("test");
        }
    
}

	@Test
	public void testDeleteCredential() {
        ServerConnection sc = new ServerConnection(null);
        try {
            //create account Note: this logins the user
            assertEquals(Response.SUCCESS, sc.createAccount("foobar", "baz"));
            
            
            //try to delete credentials with empty inputs
            assertEquals(Response.WRONG_INPT, sc.deleteCredential(""));
            //try to delete credentials with null inputs
            assertEquals(Response.WRONG_INPT, sc.deleteCredential(null));
            //try to delete credentials with tabspaces in service name
            assertEquals(Response.BAD_FORMAT, sc.deleteCredential("face\tbook"));
            //delete cred with only tabspace in service name
            assertEquals(Response.BAD_FORMAT, sc.deleteCredential("\t"));
            //delete nonexistent credential
            assertEquals(Response.NO_SVC, sc.deleteCredential("facebook"));

            //Add credentials
            assertEquals(Response.SUCCESS, sc.addCredential("facebook", "foobar", "baz"));
            //Add another credential
            assertEquals(Response.SUCCESS, sc.addCredential("gmail", "foobar2", "baz2"));

            //delete existing credential
            assertEquals(Response.SUCCESS, sc.deleteCredential("facebook"));
            //delete already deleted credential
            assertEquals(Response.NO_SVC, sc.deleteCredential("facebook"));
            
            
        } finally {
            sc.deleteAccount("baz");
        }
	}
*/
}
