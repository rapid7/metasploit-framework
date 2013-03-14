package armitage;

import console.Console;
import msf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/* A generic class to manage reading/writing to a console. Keeps the code simpler (although the Sleep code to do this is 
   simpler than this Java code. *sigh* */
public abstract class GenericTabCompletion {
	protected Console       window;

	/* state for the actual tab completion */
	protected String last      = null;
	protected Iterator tabs    = null;

	public Console getWindow() {
		return window;
	}

	public GenericTabCompletion(Console windowz) {
		this.window = windowz;

		window.addActionForKey("pressed TAB", new AbstractAction() {
			public void actionPerformed(final ActionEvent ev) {
				tabComplete(ev);
			}
		});
	}

	public abstract Collection getOptions(String text);

	private void tabCompleteFirst(String text) {
		try {
			LinkedHashSet responses = new LinkedHashSet();
			Collection options = getOptions(text);

			if (options == null)
				return;

			/* cycle through all of our options, we want to split items up to the
			   first slash. We also want them to be unique and ordered (hence the
			   linked hash set */
			Iterator i = options.iterator();
			while (i.hasNext()) {
				String option = i.next() + "";

				String begin;
				String end;

				if (text.length() > option.length()) {
					begin = option;
					end = "";
				}
				else {
					begin = option.substring(0, text.length());
					end = option.substring(text.length());
				}

				int nextSlash;
				if ((nextSlash = end.indexOf('/')) > -1 && (nextSlash + 1) < end.length()) {
					end = end.substring(0, nextSlash);
				}

				responses.add(begin + end);
			}

			responses.add(text);

			synchronized (window) {
				tabs = responses.iterator();
				last = (String)tabs.next();
			}

			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					window.getInput().setText(last);
				}
			});
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public void tabComplete(ActionEvent ev) {
		final String text = window.getInput().getText();
		if (text.length() == 0)
			return;

		synchronized (window) {
			if (tabs != null && tabs.hasNext() && text.equals(last)) {
				last = (String)tabs.next();
				window.getInput().setText(last);
				return;
			}
			else {
				new Thread(new Runnable() {
					public void run() {
						tabCompleteFirst(text);
					}
				}).start();
			}
		}
	}
}
