package ui;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;

import java.awt.*;
import java.awt.event.*;


/* A textfield with a popup menu to cut, copy, paste, and clear the textfield */
public class CopyPopup {
	protected JPopupMenu menu = null;
	protected JTextComponent component = null;

	public CopyPopup(JTextComponent component) {
		this.component = component;
		createMenu();
	}

	public void createMenu() {
		if (menu != null)
			return;

		menu = new JPopupMenu();
		JMenuItem copy = new JMenuItem("Copy", 'o');

		copy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				component.copy();
			}
		});

		menu.add(copy);

		component.addMouseListener(new MouseAdapter() {
			public void handle(MouseEvent ev) {
				if (ev.isPopupTrigger()) {
					menu.show((JComponent)ev.getSource(), ev.getX(), ev.getY());
				}
			}

			public void mousePressed(MouseEvent ev) {
				handle(ev);
			}

			public void mouseClicked(MouseEvent ev) {
				handle(ev);
			}

			public void mouseReleased(MouseEvent ev) {
				handle(ev);
			}
		});
	}
}
