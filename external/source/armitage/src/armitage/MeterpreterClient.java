package armitage;

import console.Console;
import msf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/* This is a rewritten client class to keep compatible with ConsoleClient but interface with the new
   MeterpreterSession class. This new class makes sure each command is executed and receives its output
   before the next one is executed. This prevents the Armitage UI from becoming confused */

public class MeterpreterClient implements ActionListener, MeterpreterSession.MeterpreterCallback {
	protected Console		window;
	protected MeterpreterSession	session;
	protected ActionListener	shellCommand;

	public Console getWindow() {
		return window;
	}

	public void commandComplete(String sid, Object token, Map response) {
		if (token == this || token == null) 
			processRead(response);
	}

	public void commandTimeout(String sid, Object token, Map response) {
		window.append("[*] Timed out waiting for command to complete.\n");
	}

	private void processRead(Map read) {
		try {
			if (! "".equals( read.get("data") )) {
				String text = read.get("data") + "";
				window.append(text);
			}

			if (! "".equals( read.get("prompt") )) {
				window.updatePrompt(ConsoleClient.cleanText(read.get("prompt") + ""));
			}
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public MeterpreterClient(Console window, MeterpreterSession session, ActionListener shellCommand) {
		this.window	  = window;
		this.session	  = session;
		this.shellCommand = shellCommand;
		this.session.addListener(this);

		setupListener();

		window.updatePrompt("meterpreter > ");
	}

	/* called when the associated tab is closed */
	public void actionPerformed(ActionEvent ev) {
		/* nothing we need to do for now */
	}

	protected void finalize() {
		actionPerformed(null);
	}

	public void sendString(String text) {
		window.append(window.getPromptText() + text);
		session.addCommand(this, text);
	}

	protected void setupListener() {
		window.getInput().addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				String text = window.getInput().getText() + "\n";
				window.getInput().setText("");

				if (shellCommand != null && text.trim().equals("shell")) {
					shellCommand.actionPerformed(new ActionEvent(this, 0, "shell"));
				}
				else if (shellCommand != null && text.trim().equals("screenshot")) {
					shellCommand.actionPerformed(new ActionEvent(this, 0, "screenshot"));
				}
				else if (shellCommand != null && text.trim().equals("webcam_snap")) {
					shellCommand.actionPerformed(new ActionEvent(this, 0, "webcam_snap"));
				}
				else {
					sendString(text);
				}
			}
		});
	}
}
