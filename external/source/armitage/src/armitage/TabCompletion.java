package armitage;

import console.Console;
import msf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import java.io.IOException;

/* A generic class to manage reading/writing to a console. Keeps the code simpler (although the Sleep code to do this is 
   simpler than this Java code. *sigh* */
public class TabCompletion extends GenericTabCompletion {
	protected RpcConnection connection;
	protected String        session;
	protected String        tabsCommand;

	public TabCompletion(Console window, RpcConnection connection, String session, String tabsCommand) {
		super(window);
		this.connection = connection;
		this.session = session;
		this.tabsCommand = tabsCommand;
	}

	public Collection getOptions(String text) {
		try {
			Map response = (Map)connection.execute(tabsCommand, new Object[] { session, text });

			if (response.get("tabs") == null)
				return null;

			Collection options = (Collection)response.get("tabs");
			return options;
		}
		catch (IOException ioex) {
			ioex.printStackTrace();
		}
		return null;
	}
}
