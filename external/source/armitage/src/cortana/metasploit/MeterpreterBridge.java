package cortana.metasploit;

import cortana.core.*;
import cortana.Safety;
import msf.*;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

public class MeterpreterBridge implements Loadable, Function, MeterpreterSession.MeterpreterCallback {
	protected EventManager  events;
	protected FilterManager filters;
	protected RpcConnection client;
	protected RpcConnection dserver;
	protected Map           sessions;

	private static class MeterpreterToken {
		public ScriptInstance script;
		public String         command;
		public SleepClosure   function;
	}

	public void commandComplete(String session, Object token, Map response) {
		if (!(token instanceof MeterpreterToken))
			return;

		ScriptInstance script   = ((MeterpreterToken)token).script;
		String         command  = ((MeterpreterToken)token).command;
		SleepClosure   function = ((MeterpreterToken)token).function;

		String[] first = command.split("\\s+");

		if (first.length == 0)
			return;

		Stack args = new Stack();
		args.push(FilterManager.convertAll(response.get("data")));
		args.push(SleepUtils.getScalar(command));
		args.push(SleepUtils.getScalar(session));

		if (function == null) {
			events.fireEvent("meterpreter_" + first[0].toLowerCase(), args, script);
			events.fireEvent("meterpreter", args, script);
		}
		else {
			SleepUtils.runCode(function, "complete", script, args);
		}
	}

	public void commandTimeout(String session, Object token, Map response) {
		if (!(token instanceof MeterpreterToken))
			return;

		ScriptInstance script  = ((MeterpreterToken)token).script;
		String         command = ((MeterpreterToken)token).command;
		SleepClosure   function = ((MeterpreterToken)token).function;

		Stack args = new Stack();
		args.push(SleepUtils.getScalar(command));
		args.push(SleepUtils.getScalar(session));

		if (function == null) {
			events.fireEvent("meterpreter_timeout", args, script);
		}
		else {
			SleepUtils.runCode(function, "timeout", script, args);
		}
	}

	public MeterpreterSession getSession(String sid) {
		if (sessions.containsKey(sid)) {
			return (MeterpreterSession)sessions.get(sid);
		}
		else {
			MeterpreterSession m = new MeterpreterSession(client, sid, client != dserver);
			m.addListener(this);
			sessions.put(sid, m);
			return m;
		}
	}

	public MeterpreterBridge(RpcConnection client, RpcConnection dserver, EventManager events, FilterManager filters) {
		this.client  = client;
		this.dserver = dserver;
		this.events  = events;
		this.filters = filters;

		sessions = new HashMap();
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		String sid = BridgeUtilities.getString(args, "");
		String command = BridgeUtilities.getString(args, "");

		MeterpreterSession session = getSession(sid);

		MeterpreterToken token = new MeterpreterToken();
		token.script = script;
		token.command = command;

		if (args.isEmpty()) {
			token.function = null;
		}
		else {
			SleepClosure f = BridgeUtilities.getFunction(args, script);
			token.function = f;
		}

		/* do the safety stuff */
		if (Safety.shouldAsk(script)) {
			StringBuffer description = new StringBuffer();
			description.append("<html><body><b>");
			description.append(new java.io.File(script.getName()).getName());
			description.append("</b> wants to control meterpreter <b>");
			description.append(sid);
			description.append("</b>:</html></body>\n\n<html><body><b>");
			description.append(command);
			description.append("</b></body></html>\n\nWould you like to allow this?");

			if (!Safety.ask(script, description.toString(), "meterpreter " + sid + " - '" + command + "'")) {
				return SleepUtils.getEmptyScalar();
			}
		}

		if (Safety.shouldLog(script)) {
			Safety.log(script, "meterpreter " + sid + ": '" + command + "'");
		}

		session.addCommand(token, command);

		return SleepUtils.getEmptyScalar();
	}

	public void scriptLoaded(ScriptInstance si) {
		si.getScriptEnvironment().getEnvironment().put("&m_cmd", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}
}
