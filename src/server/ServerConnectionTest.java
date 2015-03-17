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
		ServerConnection sc = new ServerConnection(null);
		assertEquals(Response.SUCCESS, sc.createAccount("cs794", "helloworld"));
		System.out.println(new File(".").getAbsolutePath());
		sc.deleteAccount("helloworld");
	
		
	}

	@Test
	public void testChangeAccountPassword() {
		fail("Not yet implemented");
	}

	@Test
	public void testDeleteAccount() {
		//ServerConnection sc = new ServerConnection(null);
		//assertEquals(Response.SUCCESS, sc.deleteAccount("helloworld"))
	}

	@Test
	public void testAuthAccount() {
		ServerConnection sc = new ServerConnection(null);
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
	    ServerConnection sc = new ServerConnection(null);
	    sc.createAccount("kl459", "test");
	    System.out.println(sc.responseGetString(sc.authAccount("kl459", "test")));
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
