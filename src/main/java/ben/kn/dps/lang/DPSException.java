package ben.kn.dps.lang;

/**
 * Encapsulation of any exceptions thrown.
 */
public class DPSException extends RuntimeException {
	private static final long serialVersionUID = 6748235936949011443L;

	public DPSException(String message) {
		super(message);
	}

	@Override
	public String toString() {
		return "DPSException: " + getMessage();
	}
}
