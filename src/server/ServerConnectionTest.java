package server;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

import server.ServerConnection.Response;

public class ServerConnectionTest {

	@Test
	public void testSaltAndHash() {
		
		fail("Not yet implemented");
	}

	@Test
	public void testCreateAccount() throws Exception{
		// 1. Create an account
		ServerConnection sc = new ServerConnection(null);
		assertEquals(Response.SUCCESS, sc.createAccount("cs794", "helloworld"));
		
		// 2. Try to create a duplicate account
		assertEquals(Response.FAIL, sc.createAccount("cs794", "helloworld"));
		
		// 3. password is empty
		//assertEquals(Response.FAIL, sc.createAccount("kl459", ""));
		
		
		// 4. password is null
		//assertEquals(Response.FAIL, sc.createAccount("kjd88", null));
		
		// 5. username is empty
		//assertEquals(Response.FAIL, sc.createAccount("", "helloworld"));
		
		
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
		assertEquals(Response.WRONG_PASS, sc.authAccount("kjd88", "test"));
		
		// 4. Authenticate with the new password
		assertEquals(Response.SUCCESS, sc.authAccount("kjd88", "test1"));
		
		// 5. Delete account
		sc.deleteAccount("test1");
		
		
	}

	@Test
	public void testDeleteAccount() {
		//ServerConnection sc = new ServerConnection(null);
		//assertEquals(Response.SUCCESS, sc.deleteAccount("helloworld"))
		fail("Not yet implemented");
	}

	@Test
	public void testAuthAccount() {
		//ServerConnection sc = new ServerConnection(null);
		//assertEquals(Response.WRONG_PASS, sc.authAccount("cs794", "halloworld"));
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