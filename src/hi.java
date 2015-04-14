import java.security.KeyStore;
import javax.net.ssl.*;

import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.io.File;


import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;
import javax.activation.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Properties;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.File;


public class hi {

	public static void main(String[] args) {
		sendSmsCode("6082258090");
	}

		protected static int sendSmsCode(String phoneNumber) 
		{
			String at = "@vtext.com";
			byte code[] = new byte[4];
			int intCode;

			new SecureRandom().nextBytes(code);
			intCode = code[0];
			// Assuming you are sending email from localhost
			String host = "localhost";
			String from = "mjv58@cornell.edu";
			//                         // Get system properties
			Properties properties = System.getProperties();
			//
			//                                         // Setup mail server
			properties.setProperty("mail.smtp.host", host);
			//                                                         
			Session session = Session.getDefaultInstance(properties);
			try{
				MimeMessage message = new MimeMessage(session);
				message.setFrom(new InternetAddress(from));
				message.addRecipient(Message.RecipientType.TO,
				new InternetAddress(phoneNumber + at));
				message.setSubject("Your verification code");
				//
				//                                                                                                                                                                                                                                  // Now set the actual message
				message.setText(Integer.toString(intCode));

				//                                                                                                                                                                                                                                                          // Send message
				Transport.send(message);
			}catch (MessagingException mex) {
				mex.printStackTrace();
			}

			return 0;

		}
	}

