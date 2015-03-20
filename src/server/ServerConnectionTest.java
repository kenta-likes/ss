package server;

import util.*;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;


public class ServerConnectionTest {

	@Test
	public void testSaltAndHash() {
		
		fail("Not yet implemented");
	}
	
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
		// 1. Create an account
		ServerConnection sc = new ServerConnection(null);
		assertEquals(Response.SUCCESS, sc.createAccount("cs794", "helloworld"));
		
		// 2. Try to create a duplicate account
		assertEquals(Response.FAIL, sc.createAccount("cs794", "helloworld"));
				
		sc.deleteAccount("helloworld");
	}

	@Test
	public void testChangeAccountPassword() {
		// 1. Create an account
		ServerConnection sc = new ServerConnection(null);
		assertEquals(Response.SUCCESS, sc.createAccount("kjd88", "test"));
		
		// 2. Change password
		assertEquals(Response.SUCCESS, sc.changeAccountPassword("test", "test1"));
		
		// 3. Authenticate with the old password
		assertEquals(Response.WRONG_INPT, sc.authAccount("kjd88", "test"));
		
		// 4. Authenticate with the new password
		assertEquals(Response.SUCCESS, sc.authAccount("kjd88", "test1"));
		
		// 5. Delete account
		sc.deleteAccount("test1");
		
	}

	@Test
	public void testDeleteAccount() {
		// 1. Create an account
		ServerConnection sc = new ServerConnection(null);
		assertEquals(Response.SUCCESS, sc.createAccount("kl459", "kenta"));
		
		// 2. Delete with wrong password
		assertEquals(Response.WRONG_INPT, sc.deleteAccount("kent"));
		
		// 3. Delete with correct password
		assertEquals(Response.SUCCESS, sc.deleteAccount("kenta"));
		
	}

	@Test
	public void testAuthAccount() {
		//ServerConnection sc = new ServerConnection(null);
		//assertEquals(Response.WRONG_INPT, sc.authAccount("cs794", "halloworld"));
		//assertEquals(Response.SUCCESS, sc.authAccount("cs794", "helloworld"));
		fail("Not yet implemented");
	}

	@Test
	public void testRetrieveCredentials() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetPassword() {
		fail("Not yet implemented");
	}

	@Test
	public void testAddCredential() {
		fail("Not yet implemented");
//	    ServerConnection sc = new ServerConnection(null);
//	    sc.createAccount("kl459", "test");
//	    System.out.println(sc.responseGetString(sc.authAccount("kl459", "test")));
	}

	@Test
	public void testUpdateCredential() {
		fail("Not yet implemented");
	}

	@Test
	public void testDeleteCredential() {
		fail("Not yet implemented");
	}

}
