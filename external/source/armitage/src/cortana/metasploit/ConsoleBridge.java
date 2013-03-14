package cortana.metasploit;

import cortana.core.*;
import cortana.*;
import msf.*;
import armitage.*;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

import javax.swing.*;

public class ConsoleBridge implements Loadable, Function, ConsoleQueue.ConsoleCallback {
	protected EventManager  events;
	protected FilterManager filters;
	protected RpcConnection client;
	protected Map           sessions;

	private static class ConsoleToken {
		public ScriptInstance script;
		public String         command;
		public SleepClosure   function;
	}

	public void commandComplete(ConsoleQueue session, Object token, String output) {
		if (!(token instanceof ConsoleToken)) {
			/* we want the console event to be the catch-all of everything */
			Stack args = new Stack();
			args.push(FilterManager.convertAll(output));
			args.push(SleepUtils.getEmptyScalar());
			args.push(SleepUtils.getScalar(session));

			/* TODO: need a hash that maps console queues to scripts */
			events.fireEvent("console", args, null);
			return;
		}

		ScriptInstance script   = ((ConsoleToken)token).script;
		String         command  = ((ConsoleToken)token).command;
		SleepClosure   function = ((ConsoleToken)token).function;
		String[] first = command.split("\\s+");

		if (first.length == 0)
			return;

		Stack args = new Stack();
		args.push(FilterManager.convertAll(output));
		args.push(SleepUtils.getScalar(command));
		args.push(SleepUtils.getScalar(session));

		if (function == null) {
			events.fireEvent("console_" + first[0].toLowerCase(), args, script);
			events.fireEvent("console", args, script);
		}
		else {
			SleepUtils.runCode(function, "complete", script, args);
		}
	}

	private ConsoleQueue getQueue(ScriptInstance script) {
		ConsoleQueue session;
		if (script.getMetadata().containsKey("%msfconsole%")) {
			session = (ConsoleQueue)script.getMetadata().get("%msfconsole%");
		}
		else {
			session = newQueue(script);
			script.getMetadata().put("%msfconsole%", session);
		}
		return session;
	}

	private ConsoleQueue newQueue(ScriptInstance script) {
		ConsoleQueue session = new ConsoleQueue(client);
		session.addListener(this);
		session.start();
		return session;
	}

	public ConsoleBridge(RpcConnection client, EventManager events, FilterManager filters) {
		this.client  = client;
		this.events  = events;
		this.filters = filters;

		sessions = new HashMap();
	}

	public Scalar evaluate(String name, ScriptInstance script, Stack args) {
		if (name.equals("&console")) {
			ConsoleQueue session = newQueue(script);
			session.addSessionListener(this);
			return SleepUtils.getScalar(session);
		}
		else if (name.equals("&cmd_set")) {
			ConsoleQueue session = (ConsoleQueue)BridgeUtilities.getObject(args);
			Scalar topitem = (Scalar)args.pop();
			session.setOptions(SleepUtils.getMapFromHash(topitem));
		}
		else if (name.equals("&cmd_echo")) {
			ConsoleQueue session = (ConsoleQueue)BridgeUtilities.getObject(args);
			session.append(BridgeUtilities.getString(args, ""));
		}
		else if (name.equals("&cmd_stop")) {
			ConsoleQueue session = (ConsoleQueue)BridgeUtilities.getObject(args);
			session.stop();
		}
		else {
			/* resolve our console */
			ConsoleQueue session = null;
			if (name.equals("&cmd")) {
				session = (ConsoleQueue)BridgeUtilities.getObject(args);
			}
			else if (name.equals("&cmd_async")) {
				session = newQueue(script);
			}
			else if (name.equals("&cmd_safe")) {
				session = getQueue(script);
			}

			/* build up our command data structure thing */
			String command = BridgeUtilities.getString(args, "");

			ConsoleToken token = new ConsoleToken();
			token.script = script;
			token.command = command;

			/* attach a function to the command if asked to */
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
				description.append("</b> wants to write to a console");
				description.append("</b>:</html></body>\n\n<html><body><b>");
				description.append(command);
				description.append("</b></body></html>\n\nWould you like to allow this?");

				if (!Safety.ask(script, description.toString(), "console - '" + command + "'")) {
					return SleepUtils.getEmptyScalar();
				}
			}

			if (Safety.shouldLog(script)) {
				Safety.log(script, "console - '" + command + "'");
			}

			/* we made it this far, go ahead and add the command to the queue */
			session.addCommand(token, command);

			/* return the console to the pool if it's an async command */
			if (name.equals("&cmd_async")) {
				session.stop();
			}

		}
		return SleepUtils.getEmptyScalar();
	}

	public void scriptLoaded(ScriptInstance si) {
		si.getScriptEnvironment().getEnvironment().put("&cmd_async", this);
		si.getScriptEnvironment().getEnvironment().put("&cmd_safe", this);
		si.getScriptEnvironment().getEnvironment().put("&cmd", this);
		si.getScriptEnvironment().getEnvironment().put("&cmd_echo", this);
		si.getScriptEnvironment().getEnvironment().put("&cmd_set", this);
		si.getScriptEnvironment().getEnvironment().put("&console", this);
		si.getScriptEnvironment().getEnvironment().put("&cmd_stop", this);
	}

	public void scriptUnloaded(ScriptInstance si) {
	}
}
