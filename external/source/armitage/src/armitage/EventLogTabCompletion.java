package armitage;

import console.Console;
import msf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import java.io.IOException;

public class EventLogTabCompletion extends GenericTabCompletion {
	protected RpcConnection connection;

	public EventLogTabCompletion(Console window, RpcConnection connection) {
		super(window);
		this.connection = connection;
	}

	public Collection getOptions(String text) {
		try {
			Map response = (Map)connection.execute("armitage.lusers", new Object[] {});

			if (response.get("lusers") == null)
				return null;

			Iterator users = ((Collection)response.get("lusers")).iterator();

			LinkedList options = new LinkedList();
			String word;
			String pre;

			if (text.endsWith(" ")) {
				word = "";
				pre  = text;
			}
			if (text.lastIndexOf(" ") != -1) {
				word = text.substring(text.lastIndexOf(" ") + 1);
				pre  = text.substring(0, text.lastIndexOf(" ") + 1);
			}
			else {
				word = text;
				pre = "";
			}

			while (users.hasNext()) {
				String user = users.next() + "";
				if (user.startsWith(word)) {
					options.add(pre + user);
				}
			}

			return options;
		}
		catch (IOException ioex) {
			ioex.printStackTrace();
		}
		return null;
	}
}
