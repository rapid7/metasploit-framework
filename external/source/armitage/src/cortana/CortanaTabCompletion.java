package cortana;

import armitage.GenericTabCompletion;
import console.Console;
import msf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

/* A generic class to manage reading/writing to a console. Keeps the code simpler (although the Sleep code to do this is 
   simpler than this Java code. *sigh* */
public class CortanaTabCompletion extends GenericTabCompletion {
	protected Cortana engine;

	public CortanaTabCompletion(Console window, Cortana engine) {
		super(window);
		this.engine = engine;
	}

	public Collection getOptions(String text) {
		return engine.commandList(text);
	}
}
