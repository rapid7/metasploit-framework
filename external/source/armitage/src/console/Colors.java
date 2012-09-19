package console;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.text.*;

/* a class for managing and parsing colors */
public class Colors {
	public static final char bold      = (char)2;
	public static final char underline = (char)31;
	public static final char color     = (char)3;
	public static final char cancel    = (char)15;
	public static final char reverse   = (char)22;

	private static final class Fragment {
		protected SimpleAttributeSet attr = new SimpleAttributeSet();
		protected StringBuffer text = new StringBuffer(32);
		protected Fragment next     = null;

		public void advance() {
			next = new Fragment();
			next.attr = (SimpleAttributeSet)attr.clone();
		}
	}

	protected boolean showcolors = true;

	public Colors(java.util.Properties prefs) {
		colorTable = new Color[16];
		colorTable[0] = Color.white;
		colorTable[1] = new Color(0, 0, 0);
		colorTable[2] = Color.decode("#3465A4");
		colorTable[3] = Color.decode("#4E9A06");
		colorTable[4] = Color.decode("#EF2929"); //new Color(255, 0, 0);
		colorTable[5] = Color.decode("#CC0000");
		colorTable[6] = Color.decode("#75507B");
		colorTable[7] = Color.decode("#C4A000");
		colorTable[8] = Color.decode("#FCE94F");
		colorTable[9] = Color.decode("#8AE234");
		colorTable[10] = Color.decode("#06989A");
		colorTable[11] = Color.decode("#34E2E2");
		colorTable[12] = Color.decode("#729FCF");
		colorTable[13] = Color.decode("#AD7FA8");
		//colorTable[14] = Color.decode("#555753");
		colorTable[14] = Color.decode("#808080");
		colorTable[15] = Color.lightGray;

		for (int x = 0; x < 16; x++) {
			String temps = prefs.getProperty("console.color_" + x + ".color", null);
			//System.err.println("console.color_" + x + ".color=\\#" + Integer.toHexString(colorTable[x].getRGB()).substring(2));
			if (temps != null) {
				colorTable[x] = Color.decode(temps);
			}
		}

		/* do we want to show colors or automatically strip all of them? */
		showcolors = "true".equals(prefs.getProperty("console.show_colors.boolean", "true"));
	}

	protected Color colorTable[];

	/* strip format codes from the text */
	public String strip(String text) {
		Fragment f = parse(text);
		return strip(f);
	}

	private String strip(Fragment f) {
		StringBuffer buffer = new StringBuffer(128);
		while (f != null) {
			buffer.append(f.text);
			f = f.next;
		}
		return buffer.toString();
	}

	private void append(StyledDocument doc, Fragment f) {
		while (f != null) {
			try {
				if (f.text.length() > 0)
					doc.insertString(doc.getLength(), f.text.toString(), f.attr);
			}
			catch (Exception ex) {
				ex.printStackTrace();
			}
			f = f.next;
		}
	}

	public void append(JTextPane console, String text) {
		StyledDocument doc = console.getStyledDocument();
		Fragment f = parse(text);
		if (showcolors) {
			append(doc, f);
		}
		else {
			append(doc, parse(strip(f)));
		}
	}

	public void set(JTextPane console, String text) {
		/* don't update that which we do not need to update */
		Fragment f = parse(text);
		if (strip(f).equals(console.getText())) {
			return;
		}

		StyledDocument doc = console.getStyledDocument();
		try {
			doc.remove(0, doc.getLength());
			if (showcolors)
				append(doc, f);
			else
				append(doc, parse(strip(f)));
		}
		catch (BadLocationException ex) { ex.printStackTrace(); }

		/* this is a dumb hack to prevent the height from getting out of whack */
		console.setSize(new Dimension(1000, console.getSize().height));
	}

	private Fragment parse(String text) {

		Fragment current = new Fragment();
		Fragment first = current;

		if (text == null)
			return current;

		char[] data = text.toCharArray();
		int fore, back;

		for (int x = 0; x < data.length; x++) {
			switch (data[x]) {
				case bold:
					current.advance();
					StyleConstants.setBold(current.next.attr, !StyleConstants.isBold(current.attr));
					current = current.next;
					break;
				case underline:
					current.advance();
					StyleConstants.setUnderline(current.next.attr, !StyleConstants.isUnderline(current.attr));
					current = current.next;
					break;
				case color:     /* look for 0-9a-f = 16 colors */
					current.advance();
					if ((x + 1) < data.length && ((data[x + 1] >= '0' && data[x + 1] <= '9') || (data[x + 1] >= 'A' && data[x + 1] <= 'F'))) {
						int index = Integer.parseInt(data[x + 1] + "", 16);
						StyleConstants.setForeground(current.next.attr, colorTable[index]);
						x += 1;
					}
					current = current.next;
					break;
				case '\n':
					current.advance();
					current = current.next;
					current.attr = new SimpleAttributeSet();
					current.text.append(data[x]);
					break;
				case cancel:
					current.advance();
					current = current.next;
					current.attr = new SimpleAttributeSet();
					break;
				default:
					current.text.append(data[x]);
			}
		}
		return first;
	}
}
