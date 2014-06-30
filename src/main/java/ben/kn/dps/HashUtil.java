package ben.kn.dps;

import java.security.MessageDigest;

/**
 * A utility class for hashing Strings using different algorithms, defined with
 * the {@link HashMethod}.
 * 
 * @author Ben (bknear@gmail.com)
 * @since Jan 29, 2013
 */
public class HashUtil {
	/**
	 * The usual default character encoding, but hard defining it to avoid
	 * complications.
	 */
	private static final String BYTE_CHARACTER_ENCODING = "ISO-8859-1";

	/**
	 * Get the hash of the given String using the default hashing mechanism.
	 * 
	 * @param text String
	 * @return String of the hashed value
	 * @throws RuntimeException
	 */
	public static String hash(String text) throws RuntimeException {
		return hash(HashMethod.SHA1, text);
	}

	/**
	 * Get the hash of the given String.
	 * 
	 * @param method HashMethod to use, or null to use default (SHA1)
	 * @param text String
	 * @return String of the hashed value
	 * @throws RuntimeException
	 */
	public static String hash(HashMethod method, String text) throws RuntimeException {
		try {
			if ( method == null ) {
				method = HashMethod.SHA1;
			}

			MessageDigest md = MessageDigest.getInstance(method.getInstance());

			md.update(text.getBytes(BYTE_CHARACTER_ENCODING), 0, text.length());

			return convertToHexString(md.digest());
		} catch (Exception e) {
			throw new RuntimeException("Couldn't hash the text given(" + text + ")", e);
		}
	}

	private static String convertToHexString(byte[] data) {
		StringBuffer buf = new StringBuffer();
		for ( int i = 0; i < data.length; i++ ) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do {
				if ( (0 <= halfbyte) && (halfbyte <= 9) )
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while ( two_halfs++ < 1 );
		}

		return buf.toString();
	}

	public static void main(String[] args) throws Exception {
		String myString = "manually added.txt";
		System.out.println("Hashing \"" + myString + "\"");

		System.out.println("Current time: " + System.currentTimeMillis());
		System.out.println(HashUtil.hash(myString));
		// confirm the same output every time
		System.out.println(HashUtil.hash(myString));
		// confirm same length and different value a different string
		System.out.println(HashUtil.hash(myString + myString));
		// re-confirm with a small string
		System.out.println(HashUtil.hash("a"));
	}
}
