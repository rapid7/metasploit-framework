package cortana;

import javax.swing.*;
import sleep.runtime.*;

/** Safety utilities */
public class Safety {
	/* should we ask the user what they want in life? */
	public static boolean shouldAsk(ScriptInstance script) {
		return (script.getDebugFlags() & Cortana.DEBUG_INTERACT_ASK) == Cortana.DEBUG_INTERACT_ASK;
	}

	/* should we log what the script is d oing? */
	public static boolean shouldLog(ScriptInstance script) {
		return (script.getDebugFlags() & Cortana.DEBUG_INTERACT_LOG) == Cortana.DEBUG_INTERACT_LOG;
	}

	/* let's log what the script is doing... for giggles */
	public static void log(ScriptInstance script, String text) {
		script.getScriptEnvironment().showDebugMessage(text);
	}

	/* let's prompt the user and act accordingly */
	public static boolean ask(ScriptInstance script, String description, String shortd) {
		int result = JOptionPane.showConfirmDialog(null, description, "Approve Script Action?", JOptionPane.YES_NO_CANCEL_OPTION);
		if (result == JOptionPane.YES_OPTION) {
			return true;
		}
		else if (result == JOptionPane.NO_OPTION) {
			Safety.log(script, "blocked " + shortd);
			return false;
		}
		else if (result == JOptionPane.CANCEL_OPTION) {
			//int flags = script.getDebugFlags() & ~Cortana.DEBUG_INTERACT_ASK;
			//script.setDebugFlags(flags);
			Safety.log(script, "user canceled script");
			script.getScriptEnvironment().flagReturn(SleepUtils.getScalar("user canceled script"), ScriptEnvironment.FLOW_CONTROL_THROW);
			return true;
		}

		return false;
	}
}
