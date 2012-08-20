package cortana.gui;

import console.Console;
import msf.*;
import armitage.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import java.io.IOException;

/* scriptable tab completion... */
public class CortanaTabCompletion extends GenericTabCompletion {
	public static interface Completer {
		public Collection getOptions(String text);
	}

	protected Completer completer;

	public CortanaTabCompletion(Console window, Completer c) {
		super(window);
		this.completer = c;
	}

	public Collection getOptions(String text) {
		return completer.getOptions(text);
	}
}
