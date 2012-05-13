package console;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;

import java.awt.*;
import java.awt.event.*;

import java.io.PrintStream;

import java.util.*;

/** A generic multi-feature console for use in the Armitage network attack tool */
public class Display extends JPanel {
	protected JTextPane  console;
	protected Properties display;
	protected Font       consoleFont;

	protected LinkedList components = new LinkedList();

	private void updateComponentLooks() {
		Color foreground = Color.decode(display.getProperty("console.foreground.color", "#ffffff"));
		Color background = Color.decode(display.getProperty("console.background.color", "#000000"));

		Iterator i = components.iterator();
		while (i.hasNext()) {
			JComponent component = (JComponent)i.next();
			component.setForeground(foreground);
			component.setBackground(background);
			component.setFont(consoleFont);

			if (component == console) {
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

	private static Map colors = new HashMap();

	public static AttributeSet getColor(String index, Properties preferences, String def) {
		synchronized (colors) {
			if (colors.get(index) == null) {
				SimpleAttributeSet attrs = new SimpleAttributeSet();
				Color temp = Color.decode(preferences.getProperty("console.color_" + index + ".color", def));
				StyleConstants.setForeground(attrs, temp);
				colors.put(index, attrs);
			}
			return (SimpleAttributeSet)colors.get(index);
		}
	}

	public void append(final String text, final String index, final String fg) {
		if (SwingUtilities.isEventDispatchThread()) {
			_append(text, index, fg);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_append(text, index, fg);
				}
			});
		}
	}

	public void _append(String text, String index, String foreground) {
		try {
			Rectangle r = console.getVisibleRect();
			StyledDocument doc = console.getStyledDocument();
			if (foreground == null) {
				doc.insertString(doc.getLength(), text, null);
			}
			else {
				doc.insertString(doc.getLength(), text, getColor(index, display, foreground));
			}
			console.scrollRectToVisible(r);
		}
		catch(Exception e) {
			System.out.println(e);
		}
	}

	public void setText(final String _text) {
		if (SwingUtilities.isEventDispatchThread()) {
			console.setText(_text);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					console.setText(_text);
				}
			});
		}
	}

	public Display() {
		this(new Properties());
	}

	public Display(Properties display) {
		this.display = display;
		consoleFont = Font.decode(display.getProperty("console.font.font", "Monospaced BOLD 14"));

		setLayout(new BorderLayout());
		setBorder(new EmptyBorder(2, 2, 2, 2));

		/* init the console */

		console = new JTextPane();
		console.setEditable(false);
		//console.setLineWrap(true);

		JScrollPane scroll = new JScrollPane(
					console, 
					ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
					ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

		add(scroll, BorderLayout.CENTER);

		components.add(console);
		components.add(scroll);
		components.add(this);

		updateComponentLooks();

			/* right-click, Copy menu, for the console */
		new ui.CopyPopup(console);

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

		setupFindShortcutFeature();
		setupPageShortcutFeature();
		setupFontShortcutFeature();

		/* work-around for Nimbus L&F */
		console.setBackground(new Color(0,0,0,0));
		Color background = Color.decode(display.getProperty("console.background.color", "#000000"));
		scroll.getViewport().setBackground(background);
		console.setOpaque(false);
	}

	private void setupFindShortcutFeature() {
		final Properties myDisplay = display;
		final Display    myConsole = this;

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

	private void changeFontSize(float difference) {
		consoleFont = consoleFont.deriveFont(consoleFont.getSize2D() + difference);
		updateComponentLooks();
	}

	public void addActionForKeyStroke(KeyStroke key, Action action) {
		console.getKeymap().addActionForKeyStroke(key, action);
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
}
