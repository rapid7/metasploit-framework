package ui;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import javax.swing.SwingUtilities;

public class KeyBindings implements KeyEventDispatcher {
	protected Map bindings = new HashMap();

	private static class ExecuteBinding implements Runnable {
		protected String     binding;
		protected KeyHandler handler;

		public ExecuteBinding(String b, KeyHandler h) {
			binding = b;
			handler = h;
		}

		public void run() {
			handler.key_pressed(binding);
		}
	}

	public KeyBindings() {
	}

	public void bind(String description, KeyHandler handler) {
		synchronized (this) {
			bindings.put(description, handler);
		}
	}

	public boolean dispatchKeyEvent(KeyEvent ev) {
		StringBuffer description = new StringBuffer();
		if (ev.getModifiers() != 0) {
			description.append(getKeyModifiers(ev));
		}

		description.append(getKeyText(ev));

		synchronized (this) {
			if (bindings.containsKey(description.toString())) {
				ev.consume();
				if (ev.getID() != KeyEvent.KEY_PRESSED) {
					return false;
				}
				else {
					SwingUtilities.invokeLater(new ExecuteBinding(description.toString(), (KeyHandler)bindings.get(description.toString())));
					return true;
				}
			}
		}

		return false;
	}

	private static String getKeyModifiers(KeyEvent ev) {
		StringBuffer modifiers = new StringBuffer();
		if (ev.isShiftDown())
			modifiers.append("Shift+");
		if (ev.isControlDown())
			modifiers.append("Ctrl+");
		if (ev.isAltDown())
			modifiers.append("Alt+");
		if (ev.isMetaDown())
			modifiers.append("Meta+");

		return modifiers.toString();
	}

	private static String getKeyText(KeyEvent ev) {
		switch (ev.getKeyCode()) {
			case KeyEvent.VK_ACCEPT:
				return "Accept";
			case KeyEvent.VK_BACK_QUOTE:
				return "Back_Quote";
			case KeyEvent.VK_BACK_SPACE:
				return "Backspace";
			case KeyEvent.VK_CAPS_LOCK:
				return "Caps_Lock";
			case KeyEvent.VK_CLEAR:
				return "Clear";
			case KeyEvent.VK_CONVERT:
				return "Convert";
			case KeyEvent.VK_DELETE:
				return "Delete";
			case KeyEvent.VK_DOWN:
				return "Down";
			case KeyEvent.VK_END:
				return "End";
			case KeyEvent.VK_ENTER:
				return "Enter";
			case KeyEvent.VK_ESCAPE:
				return "Escape";
			case KeyEvent.VK_F1:
				return "F1";
			case KeyEvent.VK_F2:
				return "F2";
			case KeyEvent.VK_F3:
				return "F3";
			case KeyEvent.VK_F4:
				return "F4";
			case KeyEvent.VK_F5:
				return "F5";
			case KeyEvent.VK_F6:
				return "F6";
			case KeyEvent.VK_F7:
				return "F7";
			case KeyEvent.VK_F8:
				return "F8";
			case KeyEvent.VK_F9:
				return "F9";
			case KeyEvent.VK_F10:
				return "F10";
			case KeyEvent.VK_F11:
				return "F11";
			case KeyEvent.VK_F12:
				return "F12";
			case KeyEvent.VK_FINAL:
				return "Final";
			case KeyEvent.VK_HELP:
				return "Help";
			case KeyEvent.VK_HOME:
				return "Home";
			case KeyEvent.VK_INSERT:
				return "Insert";
			case KeyEvent.VK_LEFT:
				return "Left";
			case KeyEvent.VK_NUM_LOCK:
				return "Num_Lock";
			case KeyEvent.VK_MULTIPLY:
				return "NumPad_*";
			case KeyEvent.VK_PLUS:
				return "NumPad_+";
			case KeyEvent.VK_COMMA:
				return "NumPad_,";
			case KeyEvent.VK_SUBTRACT:
				return "NumPad_-";
			case KeyEvent.VK_PERIOD:
				return "Period";
			case KeyEvent.VK_SLASH:
				return "NumPad_/";
			case KeyEvent.VK_PAGE_DOWN:
				return "Page_Down";
			case KeyEvent.VK_PAGE_UP:
				return "Page_Up";
			case KeyEvent.VK_PAUSE:
				return "Pause";
			case KeyEvent.VK_PRINTSCREEN:
				return "Print_Screen";
			case KeyEvent.VK_QUOTE:
				return "Quote";
			case KeyEvent.VK_RIGHT:
				return "Right";
			case KeyEvent.VK_SCROLL_LOCK:
				return "Scroll_Lock";
			case KeyEvent.VK_SPACE:
				return "Space";
			case KeyEvent.VK_TAB:
				return "Tab";
			case KeyEvent.VK_UP:
				return "Up";
			default:
				return ev.getKeyText(ev.getKeyCode());
		}
	}
}
