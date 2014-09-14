package ben.kn.dps;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import ben.kn.dps.lang.DPSException;

/**
 * The EncryptionService available for clients to use for encrypting and decrypting passwords. Suggested password length
 * is between 6 and 40 characters. 40 character password will result in a 64 byte encoded password.
 * 
 * @author Ben (bknear@gmail.com)
 */
public class EncryptionService {
	private static final String UTF8_ENCODING = "UTF-8";

	private static CryptUtil util = new CryptUtil(null);;

	/**
	 * Sets a specific salt other than one currently being used. Note, it is on you to remember your salt!
	 * 
	 * @param salt String
	 */
	public static void setSalt(String salt) {
		util.setSalt(salt.getBytes());
	}

	/**
	 * Decrypts the given encoded password to reveal the clear-text password using the default passphrase.
	 * 
	 * @param encodedPassword String to decrypt
	 * @return String of the password
	 * @throws DPSException
	 */
	public static String decrypt(String encodedPassword) throws DPSException {
		return decrypt(null, encodedPassword);
	}

	/**
	 * Decrypts the given encoded password to reveal the clear-text password.
	 * 
	 * @param passphrase String used to encrypt/decrypt, or null to use the default.
	 * @param encodedPassword String to decrypt
	 * @return String of the password
	 * @throws Exception
	 */
	public static String decrypt(String passphrase, String encodedPassword) throws DPSException {
		try {
			byte[] encodedText = Base64.decodeBase64(encodedPassword);

			byte[] result;
			if ( passphrase == null || passphrase.length() == 0 ) {
				result = util.processPassword(encodedText, Cipher.DECRYPT_MODE);
			} else {
				result = util.processPassword(passphrase, encodedText, Cipher.DECRYPT_MODE);
			}
			return new String(result, UTF8_ENCODING);
		} catch (Exception e) {
			if ( e instanceof DPSException ) {
				throw (DPSException) e;
			} else {
				throw new DPSException("Error in reading decrypted text: " + e.getMessage());
			}
		}
	}

	/**
	 * Encrypts the given password using the default passphrase.
	 * 
	 * @param password String of the password
	 * @return String of the encrypted password
	 * @throws DPSException
	 */
	public static String encrypt(String password) throws DPSException {
		return encrypt(null, password, null);
	}

	/**
	 * Encrypts the given password.
	 * 
	 * @param passphrase String used to encrypt/decrypt, null to use the default.
	 * @param password String of the password
	 * @return String of the encrypted password
	 * @throws DPSException
	 */
	public static String encrypt(String passphrase, String password) throws DPSException {
		return encrypt(passphrase, password, null);
	}

	/**
	 * Encrypts the given password, padding to an exact length before encryption.
	 * 
	 * Some guidance on length values and the length of the String returned:
	 * <ul>
	 * <li>40 will return 64</li>
	 * <li>64 will return 96</li>
	 * <li>90 will return 128</li>
	 * <li>185 will return 256</li>
	 * </ul>
	 * 
	 * @param passphrase String used to encrypt/decrypt, <code>null</code> to use the default.
	 * @param password String of the password
	 * @param length Integer of the desired length of the password text, achieved through padding. <code>null</code> to
	 *            skip padding.
	 * @return String of the encrypted password
	 * @throws DPSException
	 */
	public static String encrypt(String passphrase, String password, Integer length) throws DPSException {
		byte[] encodedText;

		StringBuilder sb = new StringBuilder();
		sb.append(password);

		if ( length != null ) {
			char t = 25;
			while ( sb.length() < length ) {
				sb.append(t++);
			}
		}

		if ( passphrase == null || passphrase.length() == 0 ) {
			encodedText = util.processPassword(sb.toString().getBytes(), Cipher.ENCRYPT_MODE);
		} else {
			encodedText = util.processPassword(passphrase, sb.toString().getBytes(), Cipher.ENCRYPT_MODE);
		}

		return Base64.encodeBase64URLSafeString(encodedText);
	}
}