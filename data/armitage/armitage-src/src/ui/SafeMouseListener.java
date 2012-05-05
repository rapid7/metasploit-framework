package ui;

import java.awt.*;
import java.awt.event.*;

public class SafeMouseListener extends MouseAdapter {
	protected MouseListener listener;

	public SafeMouseListener(MouseListener listener) {
		this.listener = listener;
	}

	public void mouseClicked(MouseEvent ev) {
		listener.mouseClicked(ev);
	}

	public void mousePressed(MouseEvent ev) {
		listener.mousePressed(ev);
	}

	public void mouseReleased(MouseEvent ev) {
		listener.mouseReleased(ev);
	}
}
