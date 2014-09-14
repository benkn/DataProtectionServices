package ben.kn.dps.util;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ben.kn.dps.EncryptionService;

public class EncryptionServiceJTest {

	EncryptionService service = new EncryptionService();
	String key = "This is a key phrase with 40 characters.";

	@Test
	public void testEncrypt() throws Exception {
		String myKey = "jumpin";
		for ( int i = 0; i < 8; i++ ) {
			String encrypted = EncryptionService.encrypt(myKey);
			System.out.println("Key Length : " + myKey.length() + "\tEncryptedValue = " + encrypted + "\tLength : "
			        + encrypted.length());
			assertTrue(encrypted != null);

			myKey += "horse";
		}

		String encrypted = EncryptionService.encrypt(key);
		System.out.println("Key Length : " + key.length() + "\tEncryptedValue = " + encrypted + "\tLength : "
		        + encrypted.length());

		encrypted = EncryptionService.encrypt("This is a key phrase with 30 characters.");
		System.out.println("Key Length : " + key.length() + "\tEncryptedValue = " + encrypted + "\tLength : "
		        + encrypted.length());
		assertTrue(encrypted != null);
	}

	@Test
	public void testCreateTestKey() throws Exception {
		String testKey = "test key";
		String result = EncryptionService.encrypt(testKey);
		System.out.println("\n\n" + testKey + " encrypted to " + result + "\n\n");
	}

	@Test
	public void testDecrypt() throws Exception {
		String result = EncryptionService.decrypt("ivycYF2O-6vAI5TP769vmw");
		assertTrue(result != null);
		assertTrue(result.equals("test key"));
	}

	@Test
	public void testProcess() throws Exception {
		System.out.println("Testing full process");
		System.out.println("base string: " + key);
		String intermediate = EncryptionService.encrypt(key);
		System.out.println("Intermediate = " + intermediate);

		String result = EncryptionService.decrypt(intermediate);

		System.out.println("Result = " + result);

		assertTrue("Values don't match", key.equals(result));

		String intermediate2 = EncryptionService.encrypt(key);
		assertTrue("Re-encryption doesn't match", intermediate.equals(intermediate2));
	}

	@Test
	public void testPadded() throws Exception {
		// maintaining minimum 6 characters, maximum 40 characters
		String[] keys = { "sixlet", "tenletters", "sixteen lettersXX", "twenty-five letters longXX", key };

		for ( String k : keys ) {
			String encrypted = EncryptionService.encrypt(null, k, 185);
			System.out.println("For '" + k + "': " + encrypted.length() + ", " + encrypted);
		}
	}
}
