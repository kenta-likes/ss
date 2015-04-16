package password;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class PasswordClassifier {
	private static HashSet<String> knownPasswords;
	
	public PasswordClassifier() {
		knownPasswords = new HashSet<String>();
		initializeDictionary();
	}


	private static void initializeDictionary() {
		try {
			File file = new File("englishwords.txt");
			BufferedReader br = new BufferedReader(new FileReader(file));
		    String line;
		    
		    while ((line = br.readLine()) != null) {
		    	knownPasswords.add(line);
		    }
		    br.close();
		} catch (Exception e)
		{
			e.printStackTrace();
			return;
		}
	}

	public boolean isStrong(String line) {
		// strength = variance * length * distance from lowest to highest char
		int i;
		double avg = 0.0;
		double variance = 0.0;
		double strength;
		double length;
		double range;
		double dictionary;
		char max = line.charAt(0), min = line.charAt(0), cur;
		for (i = 1; i < line.length(); i++)
		{
			cur = line.charAt(i);
			avg += cur;
			if (cur < min)
				min = cur;
			if (cur > max)
				max = cur;
		}
		avg = avg / line.length();
		for (i = 0; i < line.length(); i++)
		{
			variance += (line.charAt(i) - avg) * (line.charAt(i) - avg);
		}
		variance = Math.sqrt(variance) / 50.0;
		range = Math.log(1+max-min) / 4.0;
		length = line.length()/7.0;
		dictionary = getDictionaryLikeness(line);
		strength = (variance * length * range * dictionary);
		if (strength > 1.5)
		{
			return true;
		}
		return false;
	}

	private static double getDictionaryLikeness(String line) {
		int i, j;
		Pattern p1 = Pattern.compile("[a-z,A-Z]*[0-9]*");
		Pattern p2 = Pattern.compile("[0-9]*[a-z,A-Z]*");
		String l33t = unl33t(line);
		String lower = line.toLowerCase();
		//rootlen is used to ignore roots which are not fundamental to the password
		int rootlen = (int) (line.length() / 2.5);
		if (knownPasswords.contains(lower))
		{
			if (knownPasswords.contains(line))
				// the password was found in our dictionary, it is very weak
				return 0.2;
			// the password was found in our dictionary, modified a little bit with capitalization
			return 0.3;
		}
		else
		{
			for (i = 0; i < (line.length() - rootlen); i++) 
			{
				for (j = rootlen; i + j < line.length(); j++)
				{
					if (knownPasswords.contains(line.substring(i, i + j)))
					{
						// the password contains a root in our dictionary, it is more likely to be weak
						return 0.4;
					}
					if (knownPasswords.contains(lower.substring(i, i + j)))
					{
						// the password contains a root in our dictionary, modified using capitalization
						return 0.5;
					}
					else if (knownPasswords.contains(l33t.substring(i, i+j)))
					{
						// the password contains a root modified using l33tsp3@k
						return 0.6;
					}
				}
			}
			Matcher m1 = p1.matcher(line);
			Matcher m2 = p2.matcher(line);
			if (m1.matches() || m2.matches())
			{
				// the password fits the common human pattern of english prefix - numerical suffix or vice versa
				return 0.8;
			}
			// the dictionary attack failed to find a weakness, the password is more likely strong
			return 1.2;
		}
	}

	private static String unl33t(String line) {
		char[] unl33t = new char[line.length()];
		int i;
		for (i = 0; i < line.length(); i++)
		{
			switch(line.charAt(i)) {
				case ('3'):
					unl33t[i] = 'e';
					break;
				case ('0'):
					unl33t[i] = 'o';
					break;
				case ('7'):
					unl33t[i] = 't';
					break;
				case ('1'):
					unl33t[i] = 'l';
					break;
				case ('@'):
					unl33t[i] = 'a';
					break;
				default:
					unl33t[i] = line.charAt(i);
			}
		}
		return new String(unl33t);
	}
	
}
