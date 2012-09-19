package ui;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;

import java.awt.*;
import java.awt.event.*;


/* A textfield with a popup menu to cut, copy, paste, and clear the textfield */
public class CutCopyPastePopup {
	protected JPopupMenu menu = null;
	protected JTextComponent component = null;

	public CutCopyPastePopup(JTextComponent component) {
		this.component = component;
		createMenu();
	}

	public void createMenu() {
		if (menu != null)
			return;

		menu = new JPopupMenu();
		JMenuItem cut = new JMenuItem("Cut", 'C');

		cut.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				component.cut();
			}
		});

		JMenuItem copy = new JMenuItem("Copy", 'o');

		copy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				component.copy();
			}
		});

		JMenuItem paste = new JMenuItem("Paste", 'p');

		paste.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				component.paste();
			}
		});

		JMenuItem clear = new JMenuItem("Clear", 'l');

		clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				component.setText("");
			}
		});

		menu.add(cut);
		menu.add(copy);
		menu.add(paste);
		menu.add(clear);

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
