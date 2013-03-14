package cortana.metasploit;

import cortana.core.*;
import cortana.*;
import msf.*;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

import javax.swing.*;

public class ShellBridge implements Loadable, Function, ShellSession.ShellCallback {
	protected EventManager  events;
	protected FilterManager filters;
	protected RpcConnection client;
	protected RpcConnection dserver;
	protected Map           sessions;

	private static class ShellToken {
		public ScriptInstance script;
		public String         command;
		public SleepClosure   function;
	}

	public void commandUpdate(String session, Object token, String output) {
		if (!(token instanceof ShellToken))
			return;

		ScriptInstance script   = ((ShellToken)token).script;
		String         command  = ((ShellToken)token).command;
		SleepClosure   function = ((ShellToken)token).function;

		Stack args = new Stack();
		args.push(FilterManager.convertAll(output));
		args.push(SleepUtils.getScalar(command));
		args.push(SleepUtils.getScalar(session));

		if (function == null) {
			events.fireEvent("shell_read", args, script);
		}
		else {
			SleepUtils.runCode(function, "read", script, args);
		}
	}

	public void commandComplete(String session, Object token, String output) {
		if (!(token instanceof ShellToken))
			return;

		ScriptInstance script   = ((ShellToken)token).script;
		String         command  = ((ShellToken)token).command;
		SleepClosure   function = ((ShellToken)token).function;
		String[] first = command.split("\\s+");

		if (first.length == 0)
			return;

		Stack args = new Stack();
		args.push(FilterManager.convertAll(output));
		args.push(SleepUtils.getScalar(command));
		args.push(SleepUtils.getScalar(session));

		if (function == null) {
			events.fireEvent("shell_" + first[0].toLowerCase(), args, script);
			events.fireEvent("shell", args, script);
		}
		else {
			SleepUtils.runCode(function, "complete", script, args);
		}
	}

	public ShellSession getSession(String sid) {
		if (sessions.containsKey(sid)) {
			return (ShellSession)sessions.get(sid);
		}
		else {
			ShellSession m = new ShellSession(client, dserver, sid);
			m.addListener(this);
			sessions.put(sid, m);
			return m;
		}
	}

	public ShellBridge(RpcConnection client, RpcConnection dserver, EventManager events, FilterManager filters) {
		this.client  = client;
		this.dserver = dserver;
		this.events  = events;
		this.filters = filters;

		sessions = new HashMap();
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		String sid = BridgeUtilities.getString(args, "");
		String command = BridgeUtilities.getString(args, "");

		ShellSession session = getSession(sid);

		ShellToken token = new ShellToken();
		token.script = script;
		token.command = command;

		if (args.isEmpty()) {
			token.function = null;
		}
		else {
			SleepClosure f = BridgeUtilities.getFunction(args, script);
			token.function = f;
		}

		/* check our debug flags... */
		if (Safety.shouldAsk(script)) {
			StringBuffer description = new StringBuffer();
			description.append("<html><body><b>");
			description.append(new java.io.File(script.getName()).getName());
			description.append("</b> wants to write to shell session <b>");
			description.append(sid);
			description.append("</b>:</html></body>\n\n<html><body><b>");
			description.append(command);
			description.append("</b></body></html>\n\nWould you like to allow this?");

			if (!Safety.ask(script, description.toString(), "shell " + sid + ": '" + command + "'")) {
				return SleepUtils.getEmptyScalar();
			}
		}

		if (Safety.shouldLog(script)) {
			Safety.log(script, "shell " + sid + " - '" + command + "'");
		}

		/* we made it this far, go ahead and add the command to the queue */
		session.addCommand(token, command);

		return SleepUtils.getEmptyScalar();
	}

	public void scriptLoaded(ScriptInstance si) {
		si.getScriptEnvironment().getEnvironment().put("&s_cmd", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}
}
