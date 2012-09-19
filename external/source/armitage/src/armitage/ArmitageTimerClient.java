package armitage;

import java.util.*;

/** A client for the ArmitageTimer class. It's easier to have a Java class handle all this vs. using Sleep's fork mechanism. This way we get thread safety 
    for any Sleep data structures by default. */
public interface ArmitageTimerClient {
	/** return true if you want the timer to continue running. The arguments are the command, arguments, and the result of them. */
	public boolean result(String command, Object[] arguments, Map result);
}
