package cortana.core;

import java.util.*;
import sleep.runtime.*;
import sleep.bridges.*;
import sleep.interfaces.*;

public class CommandManager {
	protected Map commands;

	protected SleepClosure getCommand(String name) {
		if (commands.containsKey(name)) {
			SleepClosure temp = (SleepClosure)commands.get(name);
			if (temp.getOwner().isLoaded())
				return temp;
			else
				commands.remove(name);
		}

		return null;
	}

	/* a function to help out with tab completion */
	public List commandList(String filter) {
		Iterator i = commands.entrySet().iterator();
		List res  = new LinkedList();
		while (i.hasNext()) {
			Map.Entry temp = (Map.Entry)i.next();
			String command = temp.getKey() + "";
			SleepClosure f = (SleepClosure)temp.getValue();
			if (filter == null || command.startsWith(filter)) {
				if (f.getOwner().isLoaded()) {
					res.add(command);
				}
				else {
					i.remove();
				}
			}
		}
		return res;
	}

	public Loadable getBridge() {
		return new Commands(this);
	}

	public CommandManager() {
		commands = new HashMap();
	}

	public void registerCommand(String command, SleepClosure c) {
		commands.put(command, c);
	}

	public boolean fireCommand(String command, String args) {
		Stack tokens = new Stack();
		StringBuffer token = new StringBuffer();
		for (int x = 0; x < args.length(); x++) {
			char temp = args.charAt(x);
			if (temp == ' ') {
				if (token.length() > 0)
					tokens.add(0, SleepUtils.getScalar(token.toString()));
				token = new StringBuffer();
			}
			else if (temp == '"' && token.length() == 0) {
				for (x++ ; x < args.length() && args.charAt(x) != '"'; x++) {
					token.append(args.charAt(x));
				}
				tokens.add(0, SleepUtils.getScalar(token.toString()));
				token = new StringBuffer();
			}
			else {
				token.append(temp);
			}
		}

		if (token.length() > 0)
			tokens.add(0, SleepUtils.getScalar(token.toString()));

		tokens.pop();

		return fireCommand(command, args, tokens);
	}

	public boolean fireCommand(String command, String argz, Stack args) {
		SleepClosure c = getCommand(command);
		if (c == null)
			return false;

		SleepUtils.runCode(c, argz, null, EventManager.shallowCopy(args));
		return true;
	}
}
