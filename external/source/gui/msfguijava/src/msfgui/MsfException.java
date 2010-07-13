package msfgui;

/**
 *
 * @author scriptjunkie
 */
class MsfException extends Exception{

	public MsfException(Throwable cause) {
		super(cause);
	}

	public MsfException(String message, Throwable cause) {
		super(message, cause);
	}

	public MsfException() {
	}

	public MsfException(String string) {
		super(string);
	}

}
