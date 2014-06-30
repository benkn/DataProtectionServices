package ben.kn.dps;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * This util class processes the encryption and decryption using password-based
 * encryption (PBE). It provides a simple, pre-configured function through
 * <code>processPassword(byte[], int)</code> or a more customizable
 * <code>processPassword(String, byte[], int)</code>.
 * 
 * @author Ben (bknear@gmail.com)
 * @since Apr 1, 2013
 */
class CryptUtil {
	private final String DEFAULT_PASSPHRASE = "392lds9rl2f9szl*#&%$sdf82&#;328Lsfd8328rsd&@*(#Rlksdf1838";
	private byte[] SALT = { (byte) 0xb2, (byte) 0xa7, (byte) 0x24, (byte) 0xdd, (byte) 0x36,
			(byte) 0x37, (byte) 0x7c, (byte) 0xba };
	private final int ITERATION_COUNT = 20;
	private final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";

	private PBEParameterSpec pbeParamSpec;
	private SecretKeyFactory keyFac;
	private Cipher pbeCipher;

	CryptUtil(byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException {
		if ( salt != null )
			SALT = salt;

		// Create PBE parameter set
		pbeParamSpec = new PBEParameterSpec(SALT, ITERATION_COUNT);
		keyFac = SecretKeyFactory.getInstance(DEFAULT_ALGORITHM);

		// Create PBE Cipher
		pbeCipher = Cipher.getInstance(DEFAULT_ALGORITHM);
	}

	void setSalt(byte[] salt) {
		SALT = salt;
	}

	byte[] processPassword(byte[] textBytes, int mode) throws Exception {
		return processPassword(DEFAULT_PASSPHRASE, textBytes, mode);
	}

	byte[] processPassword(String passphrase, byte[] textBytes, int mode) throws Exception {
		// set the password that will be used for the PBE
		PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase.toCharArray());
		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

		// Initialize PBE Cipher with key and parameters
		pbeCipher.init(mode, pbeKey, pbeParamSpec);

		// Encrypt the cleartext
		return pbeCipher.doFinal(textBytes);
	}

	/**
	 * Creates a char array of exactly 56 characters, going through the string
	 * provided circularly until filled.
	 * 
	 * @param passphrase
	 * @return char[]
	 */
	@SuppressWarnings("unused")
	private static char[] selfPaddedPassphrase(String passphrase) {
		char[] characters = new char[56];
		char[] passphraseCharacters = passphrase.toCharArray();

		for ( int i = 0; i < 56; i++ ) {
			if ( i < passphraseCharacters.length ) {
				characters[i] = passphraseCharacters[i];
			} else {
				characters[i] = passphraseCharacters[i % passphraseCharacters.length];
			}
		}

		return characters;
	}

	public static void main(String[] args) throws Exception {
		CryptUtil util = new CryptUtil(null);

		String testText = "test key";
		String encrypted = new String(
				util.processPassword(testText.getBytes(), Cipher.ENCRYPT_MODE));
		String decrypted = new String(util.processPassword(encrypted.getBytes(),
				Cipher.DECRYPT_MODE));

		System.out.println("Original Password: " + testText + "  Encrypted Password: " + encrypted);
		System.out.println("Encrypted Password: " + encrypted + " Original Password: " + decrypted);

		testText = "alternate test with longer string";
		encrypted = new String(util.processPassword(testText.getBytes(), Cipher.ENCRYPT_MODE));
		decrypted = new String(util.processPassword(encrypted.getBytes(), Cipher.DECRYPT_MODE));

		System.out.println("\nOriginal Password: " + testText + "  Encrypted Password: "
				+ encrypted);
		System.out.println("Encrypted Password: " + encrypted + " Original Password: " + decrypted);

		testText = "alternate test with longer strang";
		encrypted = new String(util.processPassword(testText.getBytes(), Cipher.ENCRYPT_MODE));
		decrypted = new String(util.processPassword(encrypted.getBytes(), Cipher.DECRYPT_MODE));

		System.out.println("\nOriginal Password: " + testText + "  Encrypted Password: "
				+ encrypted);
		System.out.println("Encrypted Password: " + encrypted + " Original Password: " + decrypted);

		testText = "alternate test with longer string";
		encrypted = new String(util.processPassword(testText, testText.getBytes(),
				Cipher.ENCRYPT_MODE));
		decrypted = new String(util.processPassword(testText, encrypted.getBytes(),
				Cipher.DECRYPT_MODE));

		System.out.println("\nOriginal Password: " + testText + "  Encrypted Password: "
				+ encrypted);
		System.out.println("Encrypted Password: " + encrypted + " Original Password: " + decrypted);

		testText = "alternate test with longer strang";
		encrypted = new String(util.processPassword(testText, testText.getBytes(),
				Cipher.ENCRYPT_MODE));
		decrypted = new String(util.processPassword(testText, encrypted.getBytes(),
				Cipher.DECRYPT_MODE));

		System.out.println("\nOriginal Password: " + testText + "  Encrypted Password: "
				+ encrypted);
		System.out.println("Encrypted Password: " + encrypted + " Original Password: " + decrypted);
	}
}
