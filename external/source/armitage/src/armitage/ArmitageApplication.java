package armitage;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.image.*;

import java.awt.*;
import java.awt.event.*;

import java.util.*;

import cortana.gui.MenuBuilder;

import ui.*;

public class ArmitageApplication extends JFrame {
	protected JTabbedPane tabs = null;
	protected JSplitPane split = null;
	protected JMenuBar menus = new JMenuBar();
	protected ScreenshotManager screens = null;
	protected KeyBindings keys = new KeyBindings();
	protected MenuBuilder builder = null;

	public void setScreenshotManager(ScreenshotManager m) {
		screens = m;
	}

	public void installMenu(MouseEvent ev, String key, Stack args) {
		if (builder == null) {
			System.err.println("Menu builder was never installed! " + key);
			return;
		}

		builder.installMenu(ev, key, args);
	}

	public void setupMenu(JComponent parent, String key, Stack args) {
		if (builder == null) {
			System.err.println("Menu builder was never installed! " + key);
			return;
		}

		builder.setupMenu(parent, key, args);
	}

	public void setMenuBuilder(MenuBuilder b) {
		System.err.println("Setting up menu builder: " + b);
		builder = b;
	}

	public void bindKey(String description, KeyHandler b) {
		keys.bind(description, b);
	}

	public void addMenu(JMenuItem menu) {
		menus.add(menu);
	}

	public JMenuBar getJMenuBar() {
		return menus;
	}

	public void _removeTab(JComponent component) {
		tabs.remove(component);
		tabs.validate();
	}

	public void removeTab(final JComponent tab) {
		if (SwingUtilities.isEventDispatchThread()) {
			_removeTab(tab);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_removeTab(tab);
				}
			});
		}
	}

	public void setTop(final JComponent top) {
		if (SwingUtilities.isEventDispatchThread()) {
			_setTop(top);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_setTop(top);
				}
			});
		}
	}

	public void _setTop(JComponent top) {
		split.setTopComponent(top);
		split.setDividerLocation(0.50);
		split.setResizeWeight(0.50);
		split.revalidate();
	}

	public void nextTab() {
		tabs.setSelectedIndex((tabs.getSelectedIndex() + 1) % tabs.getTabCount());
	}

	public void previousTab() {
		if (tabs.getSelectedIndex() == 0) {
			tabs.setSelectedIndex(tabs.getTabCount() - 1);
		}
		else {
			tabs.setSelectedIndex((tabs.getSelectedIndex() - 1) % tabs.getTabCount());
		}
	}

	public void addTab(final String title, final JComponent tab, final ActionListener removeListener) {
		if (SwingUtilities.isEventDispatchThread()) {
			_addTab(title, tab, removeListener, null);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_addTab(title, tab, removeListener, null);
				}
			});
		}
	}

	public void addTab(final String title, final JComponent tab, final ActionListener removeListener, final String tooltip) {
		if (SwingUtilities.isEventDispatchThread()) {
			_addTab(title, tab, removeListener, tooltip);
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_addTab(title, tab, removeListener, tooltip);
				}
			});
		}
	}

	private static class ApplicationTab {
		public String title;
		public JComponent component;
		public ActionListener removeListener;

		public String toString() {
			return title;
		}
	}

	protected LinkedList apptabs = new LinkedList();

	public void closeActiveTab() {
		JComponent tab = (JComponent)tabs.getSelectedComponent();
		if (tab != null) {
			removeAppTab(tab, null, new ActionEvent(tab, 0, "boo!"));
		}
	}

	public void openActiveTab() {
		JComponent tab = (JComponent)tabs.getSelectedComponent();
		if (tab != null) {
			popAppTab(tab);
		}
	}

	public void snapActiveTab() {
		JComponent tab = (JComponent)tabs.getSelectedComponent();
		Iterator i = apptabs.iterator();
		while (i.hasNext()) {
			ApplicationTab t = (ApplicationTab)i.next();
			if (t.component == tab) {
				snapAppTab(t.title, tab);
			}
		}
	}

	public void addAppTab(String title, JComponent component, ActionListener removeListener) {
		ApplicationTab t = new ApplicationTab();
		t.title = title;
		t.component = component;
		t.removeListener = removeListener;
		apptabs.add(t);
	}

	public void popAppTab(Component tab) {
		Iterator i = apptabs.iterator();
		while (i.hasNext()) {
			final ApplicationTab t = (ApplicationTab)i.next();
			if (t.component == tab) {
				tabs.remove(t.component);
				i.remove();

				/* pop goes the tab! */
				final JFrame r = new JFrame(t.title);
				r.setIconImages(getIconImages());
				r.setLayout(new BorderLayout());
				r.add(t.component, BorderLayout.CENTER);
				r.pack();
				t.component.validate();

				r.addWindowListener(new WindowAdapter() {
					public void windowClosing(WindowEvent ev) {
						if (t.removeListener != null)
							t.removeListener.actionPerformed(new ActionEvent(ev.getSource(), 0, "close"));
					}

					public void windowOpened(WindowEvent ev) {
						r.setState(JFrame.NORMAL);
						t.component.requestFocusInWindow();
					}

					public void windowActivated(WindowEvent ev) {
						t.component.requestFocusInWindow();
					}
				});

				r.setState(JFrame.ICONIFIED);
				r.setVisible(true);
			}
		}
	}

	public void snapAppTab(String title, Component tab) {
		/* capture the current tab in an image */
		BufferedImage image = new BufferedImage(tab.getWidth(), tab.getHeight(), BufferedImage.TYPE_4BYTE_ABGR);
		Graphics g = image.getGraphics();
		tab.paint(g);
		g.dispose();

		if (screens != null) {
			screens.saveScreenshot(image, title);
		}
	}

	public void removeAppTab(Component tab, String title, ActionEvent ev) {
		Iterator i = apptabs.iterator();
		String titleshort = title != null ? title.split(" ")[0] : "%b%";
		while (i.hasNext()) {
			ApplicationTab t = (ApplicationTab)i.next();
			String tshort = t.title != null ? t.title.split(" ")[0] : "%a%";
			if (t.component == tab || tshort.equals(titleshort)) {
				tabs.remove(t.component);

				if (t.removeListener != null)
					t.removeListener.actionPerformed(ev);

				i.remove();
			}
		}
	}

	public void _addTab(final String title, final JComponent tab, final ActionListener removeListener, final String tooltip) {
		final Component component = tabs.add("", tab);
		final JLabel label = new JLabel(title + "   ");

		JPanel control = new JPanel();
		control.setOpaque(false);
		control.setLayout(new BorderLayout());
		control.add(label, BorderLayout.CENTER);

		if (tab instanceof Activity) {
			((Activity)tab).registerLabel(label);
		}

		JButton close = new JButton("X");
		close.setOpaque(false);
		close.setContentAreaFilled(false);
		close.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
		control.add(close, BorderLayout.EAST);

		if (tooltip != null) {
			close.setToolTipText(tooltip);
		}

		int index = tabs.indexOfComponent(component);
		tabs.setTabComponentAt(index, control);

		addAppTab(title, tab, removeListener);

		close.addMouseListener(new MouseAdapter() {
			public void check(MouseEvent ev) {
				if (ev.isPopupTrigger()) {
					JPopupMenu menu = new JPopupMenu();

					JMenuItem a = new JMenuItem("Open in window", 'O');
					a.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent ev) {
							popAppTab(component);
						}
					});

					JMenuItem b = new JMenuItem("Close like tabs", 'C');
					b.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent ev) {
							removeAppTab(null, title, ev);
						}
					});

					JMenuItem c = new JMenuItem("Save screenshot", 'S');
					c.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent ev) {
							snapAppTab(title, tab);
						}
					});

					JMenuItem d = new JMenuItem("Rename Tab", 'R');
					d.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent ev) {
							String text = JOptionPane.showInputDialog("Rename tab to:", (label.getText() + "").trim());
							if (text != null)
								label.setText(text + "   ");
						}
					});

					menu.add(a);
					menu.add(c);
					menu.add(d);
					menu.addSeparator();
					menu.add(b);

					menu.show((Component)ev.getSource(), ev.getX(), ev.getY());
					ev.consume();
				}
			}

			public void mouseClicked(MouseEvent ev) {
				check(ev);
			}

			public void mousePressed(MouseEvent ev) {
				check(ev);
			}

			public void mouseReleased(MouseEvent ev) {
				check(ev);
			}
		});

		close.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				if  ((ev.getModifiers() & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK) {
					popAppTab(component);
				}
				else if  ((ev.getModifiers() & ActionEvent.SHIFT_MASK) == ActionEvent.SHIFT_MASK) {
					removeAppTab(null, title, ev);
				}
				else {
					removeAppTab(component, null, ev);
				}
				System.gc();
			}
		});

		component.addComponentListener(new ComponentAdapter() {
			public void componentShown(ComponentEvent ev) {
				if (component instanceof Activity) {
					((Activity)component).resetNotification();
				}

				component.requestFocusInWindow();
				System.gc();
			}
		});

		tabs.setSelectedIndex(index);
		component.requestFocusInWindow();
	}

	public ArmitageApplication() {
		super();
		tabs = new DraggableTabbedPane();
		setLayout(new BorderLayout());

		/* place holder */
		JPanel panel = new JPanel();

		/* add our menubar */
		add(menus, BorderLayout.NORTH);

		split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, panel, tabs);
		split.setOneTouchExpandable(true);

		/* add our tabbed pane */
		add(split, BorderLayout.CENTER);

		/* setup our key bindings */
		KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(keys);

		/* ... */
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
}
