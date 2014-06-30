package ben.kn.dps;

/**
 * Enum for specific methods of hashing -- MD5, SHA_256, and SHA1.
 * 
 * @author Ben (bknear@gmail.com)
 * @since Jan 29, 2013
 */
public enum HashMethod {
	MD5("MD5"), SHA_256("SHA-256"), SHA1("SHA1");

	private String instance;

	HashMethod(String instance) {
		this.instance = instance;
	}

	public String getInstance() {
		return instance;
	}
}