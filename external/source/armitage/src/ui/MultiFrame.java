package ui;

import javax.swing.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;

import java.util.*;

import armitage.ArmitageApplication;
import msf.*;

/* A class to host multiple Armitage instances in one frame. Srsly */
public class MultiFrame extends JFrame implements KeyEventDispatcher {
	protected JToolBar            toolbar;
	protected JPanel              content;
	protected CardLayout          cards;
	protected LinkedList          buttons;
	protected Properties          prefs;

	private static class ArmitageInstance {
		public ArmitageApplication app;
		public JToggleButton       button;
		public RpcConnection       client;
	}

	public void setPreferences(Properties prefs) {
		this.prefs = prefs;
	}

	public Properties getPreferences() {
		return prefs;
	}

	public Map getClients() {
		synchronized (buttons) {
			Map r = new HashMap();

			Iterator i = buttons.iterator();
			while (i.hasNext()) {
				ArmitageInstance temp = (ArmitageInstance)i.next();
				r.put(temp.button.getText(), temp.client);
			}
			return r;
		}
	}

	public void setTitle(ArmitageApplication app, String title) {
		if (active == app)
			setTitle(title);
	}

	protected ArmitageApplication active;

	/* is localhost running? */
	public boolean checkLocal() {
		synchronized (buttons) {
			Iterator i = buttons.iterator();
			while (i.hasNext()) {
				ArmitageInstance temp = (ArmitageInstance)i.next();
				if ("localhost".equals(temp.button.getText())) {
					return true;
				}
			}
			return false;
		}
	}

	public boolean dispatchKeyEvent(KeyEvent ev) {
		if (active != null) {
			return active.getBindings().dispatchKeyEvent(ev);
		}
		return false;
	}

	public static final void setupLookAndFeel() {
		try {
			for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
				if ("Nimbus".equals(info.getName())) {
					UIManager.setLookAndFeel(info.getClassName());
					break;
				}
			}
		}
		catch (Exception e) {
		}
	}

	public void closeConnect() {
		synchronized (buttons) {
			if (buttons.size() == 0) {
				System.exit(0);
			}
		}
	}

	public void quit() {
		synchronized (buttons) {
			ArmitageInstance temp = null;
			content.remove(active);
			Iterator i = buttons.iterator();
			while (i.hasNext()) {
				temp = (ArmitageInstance)i.next();
				if (temp.app == active) {
					toolbar.remove(temp.button);
					i.remove();
					break;
				}
			}

			if (buttons.size() == 0) {
				System.exit(0);
			}
			else if (buttons.size() == 1) {
				remove(toolbar);
				validate();
			}

			if (i.hasNext()) {
				temp = (ArmitageInstance)i.next();
			}
			else {
				temp = (ArmitageInstance)buttons.getFirst();
			}

			set(temp.button);
		}
	}

	public MultiFrame() {
		super("");

		setLayout(new BorderLayout());

		/* setup our toolbar */
		toolbar = new JToolBar();

		/* content area */
		content = new JPanel();
		cards   = new CardLayout();
		content.setLayout(cards);

		/* setup our stuff */
		add(content, BorderLayout.CENTER);

		/* buttons?!? :) */
		buttons = new LinkedList();

		/* do this ... */
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		/* some basic setup */
		setSize(800, 600);
		setExtendedState(JFrame.MAXIMIZED_BOTH);

		/* all your keyboard shortcuts are belong to me */
		KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(this);
	}

	protected void set(JToggleButton button) {
		synchronized (buttons) {
			/* set all buttons to the right state */
			Iterator i = buttons.iterator();
			while (i.hasNext()) {
				ArmitageInstance temp = (ArmitageInstance)i.next();
				if (temp.button.getText().equals(button.getText())) {
					temp.button.setSelected(true);
					active = temp.app;
					setTitle(active.getTitle());
				}
				else {
					temp.button.setSelected(false);
				}
			}

			/* show our cards? */
			cards.show(content, button.getText());
			active.touch();
		}
	}

	public void addButton(String title, final ArmitageApplication component, RpcConnection conn) {
		synchronized (buttons) {
			final ArmitageInstance a = new ArmitageInstance();
			a.button = new JToggleButton(title);
			a.button.setToolTipText(title);
			a.app    = component;
			a.client = conn;

			a.button.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent ev) {
					set((JToggleButton)ev.getSource());
				}
			});

			a.button.addMouseListener(new MouseAdapter() {
				public void check(MouseEvent ev) {
					if (ev.isPopupTrigger()) {
						final JToggleButton source = a.button;
						JPopupMenu popup = new JPopupMenu();
						JMenuItem  rename = new JMenuItem("Rename");
						rename.addActionListener(new ActionListener() {
							public void actionPerformed(ActionEvent ev) {
								String name = JOptionPane.showInputDialog("Rename to?", source.getText());
								if (name != null) {
									content.remove(component);
									content.add(component, name);
									source.setText(name);
									set(source);
								}
							}
						});
						popup.add(rename);
						popup.show((JComponent)ev.getSource(), ev.getX(), ev.getY());
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

			toolbar.add(a.button);
			content.add(component, title);
			buttons.add(a);
			set(a.button);

			if (buttons.size() == 1) {
				show();
			}
			else if (buttons.size() == 2) {
				add(toolbar, BorderLayout.SOUTH);
			}
			validate();
		}
	}
}
