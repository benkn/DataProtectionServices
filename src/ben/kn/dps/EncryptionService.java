package ben.kn.dps;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import ben.kn.dps.lang.DPSException;

/**
 * The EncryptionService available for clients to use for encrypting and
 * decrypting passwords. Suggested password length is between 6 and 40
 * characters. 40 character password will result in a 64 byte encoded password.
 * 
 * @author Ben (bknear@gmail.com)
 */
public class EncryptionService {
	private static final String UTF8_ENCODING = "UTF-8";

	private static CryptUtil util;

	public EncryptionService() throws DPSException {
		try {
			util = new CryptUtil(null);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new DPSException(e.getMessage());
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			throw new DPSException(e.getMessage());
		}
	}

	/**
	 * Use this function to set a specific salt other than one currently being
	 * used. Note, it is on you to remember your salt!
	 * 
	 * @param salt String
	 */
	public static void setSalt(String salt) {
		util.setSalt(salt.getBytes());
	}

	/**
	 * Decrypt the given encoded password to reveal the clear-text password.
	 * 
	 * @param encodedPassword String to decrypt
	 * @return String of the password
	 * @throws Exception
	 */
	public static String decrypt(String encodedPassword) throws Exception {
		byte[] encodedText = Base64.decodeBase64(encodedPassword);
		byte[] result = util.processPassword(encodedText, Cipher.DECRYPT_MODE);
		return new String(result, UTF8_ENCODING);
	}

	/**
	 * Decrypt the given encoded password to reveal the clear-text password.
	 * 
	 * @param passphrase String used to encrypt/decrypt
	 * @param encodedPassword String to decrypt
	 * @return String of the password
	 * @throws Exception
	 */
	public static String decrypt(String passphrase, String encodedPassword) throws Exception {
		byte[] encodedText = Base64.decodeBase64(encodedPassword);
		byte[] result = util.processPassword(passphrase, encodedText, Cipher.DECRYPT_MODE);
		return new String(result, UTF8_ENCODING);
	}

	/**
	 * Encrypt the given password.
	 * 
	 * @param password String of the password
	 * @return String of the encrypted password
	 * @throws Exception
	 */
	public static String encrypt(String password) throws Exception {
		byte[] encodedText = util.processPassword(password.getBytes(), Cipher.ENCRYPT_MODE);
		return Base64.encodeBase64URLSafeString(encodedText);
	}

	/**
	 * Encrypt the given password.
	 * 
	 * @param passphrase String used to encrypt/decrypt
	 * @param password String of the password
	 * @return String of the encrypted password
	 * @throws Exception
	 */
	public static String encrypt(String passphrase, String password) throws Exception {
		byte[] encodedText = util.processPassword(passphrase, password.getBytes(),
				Cipher.ENCRYPT_MODE);
		return Base64.encodeBase64URLSafeString(encodedText);
	}
}