DataProtectionServices
======================

Utilities for encryption, decryption, and other security services.

Use the EncryptionService to encrypt and decrypt passwords or other text.

## Usage Examples
All the methods from the EncryptionService are statically accessible. If you want to encrypt text:

	String encrypted = EncryptionService.encrypt(source);
	
If you want to decrypt text:

	String decrypted = EncryptionService.decrypt(encrypted);
	
For more security, it is recommended to use your own passphrase, rather than the one given in the code of this open source project. It is visible to help others improve or construct their own encryption utility.

	String myPassphrase = "My passphrase that's not the default";
	String encrypted = EncryptionService.encrypt(myPassphrase, source);
	String decrypted = EncryptionService.decrypt(myPassphrase, encrypted);
	
For added control over the process, the EncryptionService can automatically pad the given text to create consistent output. In this example, EncryptionService is told to make whatever value in `source` to lengthen to 40 characters if it is less so. An example of using this would be to tell users to create a password with a minimum and maximum length, then use the padding to create consistent lengths of encrypted results. 

	String encrypted = EncryptionService.encrypt(myPassphrase, source, 40);
	

## Release notes for Data Protection Services:
### DPS 0.6
- Updated exception handling and commenting.
- Added a padded implementation to return consistent lengths of encrypted texts.

----------------------------------------
### DPS 0.5
- Migrating to Maven for packaging.

----------------------------------------
### DPS 0.3
- Adding the ability for clients to set the salt value. 
- Adding the HashUtil 
