package console;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;

import java.awt.*;
import java.awt.event.*;

import java.io.PrintStream;

import java.util.*;

import armitage.Activity;

/** A generic multi-feature console for use in the Armitage network attack tool */
public class Console extends JPanel implements FocusListener {
	protected JTextArea  console;
	protected JTextField input;
	protected JLabel     prompt;

	protected PrintStream log = null;

	protected Properties display;
	protected Font       consoleFont;

	protected ClickListener clickl;

	protected String defaultPrompt = "meterpreter > ";

	protected LinkedList components = new LinkedList();
	protected ListIterator history = new LinkedList().listIterator(0);

	public void addWordClickListener(ActionListener l) {
		clickl.addListener(l);
	}

	public void writeToLog(PrintStream p) {
		log = p;
	}

	public void setDefaultPrompt(String p) {
		defaultPrompt = p;
	}

	public void setPopupMenu(ConsolePopup menu) {
		clickl.setPopup(menu);
	}

	public class ClickListener extends MouseAdapter {
		protected LinkedList listeners = new LinkedList();
		protected ConsolePopup popup   = null;
		protected Console    parent    = null;

		public ClickListener(Console parent) {
			this.parent = parent;
		}
	
		public void setPopup(ConsolePopup popup) {
			this.popup = popup;
		}

		public void addListener(ActionListener l) {
			listeners.add(l);
		}

		public void mousePressed(MouseEvent ev) {
			checkPopup(ev);
		}

		public void mouseReleased(MouseEvent ev) {
			checkPopup(ev);
		}

		public void checkPopup(MouseEvent ev) {
			if (ev.isPopupTrigger()) {
				if (popup != null && console.getSelectedText() == null) {
					String result = resolveWord();
					popup.showPopup(result, ev);
				}
				else {
					getPopupMenu((JTextComponent)ev.getSource()).show((JComponent)ev.getSource(), ev.getX(), ev.getY());
				}
			}
		}

		public void mouseClicked(MouseEvent ev) {
			if (!ev.isPopupTrigger()) {
				String result = resolveWord();
				Iterator i = listeners.iterator();
				ActionEvent event = new ActionEvent(parent, 0, result);

				if (!"".equals(result)) {
					while (i.hasNext()) {
						ActionListener l = (ActionListener)i.next();
						l.actionPerformed(new ActionEvent(parent, 0, result));
					}
				}
			}
			else {
				checkPopup(ev);
			}
		}

		public String resolveWord() {
			int position = console.getCaretPosition();
			String data  = console.getText();

			int start = data.lastIndexOf(" ", position);
			int end = data.indexOf(" ", position);

			if (start == -1)
				start = 0;

			if (end == -1)
				end = data.length();

			if (end >= start) {
				String temp = data.substring(start, end).trim();
				int a = temp.indexOf("\n");
				if (a > 0) {
					return temp.substring(0, a);					
				}
				return temp;
			}

			return null;
		}
	}

	public JTextField getInput() {
		return input;
	}

	public void updateProperties(Properties display) {
		this.display = display;
		updateComponentLooks();
	}

	private void updateComponentLooks() {
		Color foreground = Color.decode(display.getProperty("console.foreground.color", "#ffffff"));
		Color background = Color.decode(display.getProperty("console.background.color", "#000000"));

		Iterator i = components.iterator();
		while (i.hasNext()) {
			JComponent component = (JComponent)i.next();
			component.setForeground(foreground);
			component.setBackground(background);
			component.setFont(consoleFont);

			if (component == console || component == prompt) {
				component.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));
			}
			else {
				component.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
			}

			if (component instanceof JTextComponent) {
				JTextComponent tcomponent = (JTextComponent)component;
				tcomponent.setCaretColor(foreground.brighter());
			}
		}
	}

	public String getPromptText() {
		return prompt.getText();
	}

	protected boolean promptLock = false;

	/* this function is not thread safe */
	public void setPrompt(String text) {
		String bad = "\ufffd\ufffd";
		if (text.equals(bad) || text.equals("null")) {
			prompt.setText(defaultPrompt);
		}
		else {
			defaultPrompt = text;
			prompt.setText(text);
		}
	}

	/** updates the prompt. This is a thread-safe funtion */
	public void updatePrompt(final String _prompt) {
		if (SwingUtilities.isEventDispatchThread()) {
			setPrompt(_prompt);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					if (!promptLock)
						setPrompt(_prompt);
				}
			});
		}
	}

	protected void appendToConsole(String _text) {
		if (_text.endsWith("\n") || _text.endsWith("\r")) {
			if (!promptLock) {
				console.append(_text);
				if (log != null)
					log.print(_text);
			}
			else {
				console.append(prompt.getText());
			}

			if (!_text.startsWith(prompt.getText()))
				promptLock = false;
		}
		else {
			int breakp = _text.lastIndexOf("\n");

			if (breakp != -1) {
				console.append(_text.substring(0, breakp + 1));
				prompt.setText(_text.substring(breakp + 1) + " ");
				if (log != null)
					log.print(_text.substring(0, breakp + 1));
			}
			else {
				prompt.setText(_text);
			}
			promptLock = true;
		}


		if (console.getDocument().getLength() >= 1) {
			console.setCaretPosition(console.getDocument().getLength() - 1);
		}
	}

	/** appends the text. This is a thread-safe function */
	public void append(final String _text) {
		if (SwingUtilities.isEventDispatchThread()) {
			appendToConsole(_text);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					appendToConsole(_text);
				}
			});
		}
	}

	protected JPanel bottom = null;

	/** call this to remove the input area */
	public void noInput() {
		if (SwingUtilities.isEventDispatchThread()) {
			remove(bottom);
			validate();
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					remove(bottom);
					validate();
				}
			});
		}
	}

	public Console() {
		this(new Properties());
	}

	public Console(Properties display) {
		this.display = display;
		consoleFont = Font.decode(display.getProperty("console.font.font", "Monospaced BOLD 14"));

		setLayout(new BorderLayout());
		setBorder(new EmptyBorder(2, 2, 2, 2));

		/* init the console */

		console = new JTextArea();
		console.setEditable(false);
		console.setLineWrap(true);
		console.addFocusListener(this);

		JScrollPane scroll = new JScrollPane(
					console, 
					ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
					ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

		add(scroll, BorderLayout.CENTER);

		/* init the prompt */
		
		prompt = new JLabel();

		/* init the input */

		input = new JTextField();

		/* gymnastics because Java shares a static keymap among all textfields by default... grrr */

		input.setKeymap(JTextField.addKeymap(null, input.getKeymap()));

		/* handle the popup menu */
		
		input.addMouseListener(new MouseAdapter() {
			public void checkEvent(MouseEvent e) {
				if (e.isPopupTrigger()) {
					getPopupMenu((JTextComponent)e.getSource()).show((JComponent)e.getSource(), e.getX(), e.getY());
				}
			}

			public void mouseClicked(MouseEvent e) { checkEvent(e); }
			public void mousePressed(MouseEvent e) { checkEvent(e); }
			public void mouseReleased(MouseEvent e) { checkEvent(e); }
		});

		/* do this so I can bind the Tab key */

		input.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, new HashSet());
		input.setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS, new HashSet());
		input.setFocusTraversalKeys(KeyboardFocusManager.UP_CYCLE_TRAVERSAL_KEYS, new HashSet());

		/* bottom */

		bottom = new JPanel();
		bottom.setLayout(new BorderLayout());

		bottom.add(input, BorderLayout.CENTER);
		bottom.add(prompt, BorderLayout.WEST);

		add(bottom, BorderLayout.SOUTH);

		/* keep track of components that we want to make pretty */

		components.add(input);
		components.add(console);
		components.add(scroll);
		components.add(prompt);
		components.add(bottom);
		components.add(this);

		updateComponentLooks();

		/* add keyboard shortcuts */

		/* Alt+K - clear screen */
		addActionForKeySetting("console.clear_screen.shortcut", "ctrl K", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				console.setText("");
			}
		});

		/* Ctrl+A - select all */
		addActionForKeySetting("console.select_all.shortcut", "ctrl A", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				console.requestFocus();
				console.selectAll();
			}
		});

		/* Escape - clear input buffer */
		addActionForKeySetting("console.clear_buffer.shortcut", "ESCAPE", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				input.setText("");
			}
		});

		setupFindShortcutFeature();
		setupPageShortcutFeature();
		setupFontShortcutFeature();
		setupHistoryFeature();

		/* setup our word click listener */
		clickl = new ClickListener(this);
		console.addMouseListener(clickl);
	}

	public JPopupMenu getPopupMenu(final JTextComponent _component) {
		JPopupMenu menu = new JPopupMenu();
		
		JMenuItem cut = new JMenuItem("Cut", 'C');
		JMenuItem copy = new JMenuItem("Copy", 'o');
		JMenuItem paste = new JMenuItem("Paste", 'P');
		JMenuItem clear = new JMenuItem("Clear", 'l');

		if (_component.isEditable())
			menu.add(cut);

		menu.add(copy);
		menu.add(paste);
		menu.add(clear);
		
		cut.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				_component.cut();
			}
		});

		copy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				_component.copy();
			}
		});

		cut.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				_component.cut();
			}
		});

		paste.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				input.paste();
			}
		});

		clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				_component.setText("");
			}
		});

		return menu;
	}

	private void setupFindShortcutFeature() {
		final Properties myDisplay = display;
		final Console    myConsole = this;

		addActionForKeySetting("console.find.shortcut", "ctrl pressed F", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				Color highlight = Color.decode(myDisplay.getProperty("console.highlight.color", "#0000cc"));

				final SearchPanel search = new SearchPanel(console, highlight);
				final JPanel north = new JPanel();

				JButton goaway = new JButton("X ");
				SearchPanel.removeBorderFromButton(goaway);

				goaway.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent ev) {
						myConsole.remove(north);
						myConsole.validate();
						search.clear();
					}
				});
				
				north.setLayout(new BorderLayout());
				north.add(search, BorderLayout.CENTER);
				north.add(goaway, BorderLayout.EAST);

				myConsole.add(north, BorderLayout.NORTH);
				myConsole.validate();				
		
				search.requestFocusInWindow();
				search.requestFocus();
			}
		});
	}

	private void setupFontShortcutFeature() {
		addActionForKeySetting("console.font_size_plus.shortcut", "ctrl EQUALS", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				changeFontSize(1.0f);
			}
		});

		addActionForKeySetting("console.font_size_minus.shortcut", "ctrl MINUS", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				changeFontSize(-1.0f);
			}
		});

		/* Ctrl+0 - reset the font to the default size */
		addActionForKeySetting("console.font_size_reset.shortcut", "ctrl pressed 0", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				consoleFont = Font.decode(display.getProperty("console.font.font", "Monospaced BOLD 14"));
				updateComponentLooks();
			}
		});
	}

	private void setupPageShortcutFeature() {
		addActionForKeySetting("console.page_up.shortcut", "pressed PAGE_UP", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				Rectangle visible = new Rectangle(console.getVisibleRect());
				Rectangle scrollme = new Rectangle(0, (int)( visible.getY() - (visible.getHeight() / 2) ), 1, 1);

				if (scrollme.getY() <= 0) {
					visible.setLocation(0, 0);
				}

				console.scrollRectToVisible(scrollme);
			}
		});

		addActionForKeySetting("console.page_down.shortcut", "pressed PAGE_DOWN", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				Rectangle visible = new Rectangle(console.getVisibleRect());
				Rectangle scrollme = new Rectangle(0, (int)( visible.getY() + visible.getHeight() + (visible.getHeight() / 2) ), 1, 1);
				
				if (scrollme.getY() >= console.getHeight()) {
					visible.setLocation(0, console.getHeight());
				}

				console.scrollRectToVisible(scrollme);
			}
		});
	}

	/* handle the keyboard history stuff */
	private void setupHistoryFeature() {
		input.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				if (!"".equals(ev.getActionCommand()))
					history.add(ev.getActionCommand());
			}
		});

		addActionForKeySetting("console.history_previous.shortcut", "UP", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				if (history.hasPrevious()) {
					input.setText((String)history.previous());
				}
				else {
					input.setText("");
				}
			}
		});

		addActionForKeySetting("console.history_next.shortcut", "DOWN", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				if (history.hasNext()) {
					input.setText((String)history.next());
				}
				else {
					input.setText("");
				}
			}
		});
	}

	private void changeFontSize(float difference) {
		consoleFont = consoleFont.deriveFont(consoleFont.getSize2D() + difference);
		updateComponentLooks();
	}

	public void addActionForKeyStroke(KeyStroke key, Action action) {
		input.getKeymap().addActionForKeyStroke(key, action);
	}

	public void addActionForKey(String key, Action action) {
		addActionForKeyStroke(KeyStroke.getKeyStroke(key), action);
	}

	public void addActionForKeySetting(String key, String dvalue, Action action) {
		KeyStroke temp = KeyStroke.getKeyStroke(display.getProperty(key, dvalue));
		if (temp != null) {
			addActionForKeyStroke(temp, action);
		}
	}

	/* focus listener for our input thing */

	public void focusGained(FocusEvent ev) {
		if (!ev.isTemporary() && ev.getComponent() == console) {
			/* this is a work-around for Windows where the user can't highlight
			   text because of this attempt to get focus back to the input area */
			if ((System.getProperty("os.name") + "").indexOf("Windows") == -1 && (System.getProperty("os.name") + "").indexOf("Mac") == -1)
				input.requestFocusInWindow();
		}
	}

	public boolean requestFocusInWindow() {
		return input.requestFocusInWindow();
	}

	public void focusLost(FocusEvent ev) {

	}
}
