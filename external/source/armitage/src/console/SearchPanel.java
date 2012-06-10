package console;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;

import java.awt.*;
import java.awt.event.*;

import java.util.*;

/** a search panel for use with a JTextComponent */
public class SearchPanel extends JPanel implements ActionListener {
	protected JTextField     search = null;
	protected JLabel         status = null;
	protected JTextComponent component = null;
	protected int		 index = 0;
	protected Color          highlight = null;

	public void actionPerformed(ActionEvent event) {
		if (event.getActionCommand().equals(">")) {
			index++;
			scrollToIndex();
		}
		else if (event.getActionCommand().equals("<")) {
			index--;
			scrollToIndex();
		}
		else {
			searchBuffer();
			scrollToIndex();
		}
	}

	private void scrollToIndex() {
		Highlighter.Highlight highlights[] = component.getHighlighter().getHighlights();

		if (highlights.length == 0) {
			if (search.getText().trim().length() > 0)
				status.setText("Phrase not found");
			return;
		}

		try {
			if (index < 0) {
				index = (highlights.length - 1) - index;
			}

			int offset = index % highlights.length;

			status.setText((offset + 1) + " of " + highlights.length);

			int position = highlights[offset].getStartOffset();
			Rectangle location = component.modelToView(position);
			component.scrollRectToVisible(location);
		}
		catch (BadLocationException ex) {
			//...
		}
	}

	private void searchBuffer() {
		clear();

		String searchstr = search.getText().trim();

		if (searchstr.length() == 0)
			return;

		Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter( highlight );

		try {
			String text = component.getText();

			/* another windows work-around... */
			if ((System.getProperty("os.name") + "").indexOf("Windows") != -1) {
				text = text.replaceAll("\r\n", "\n");
			}

			int lastIndex = -1;
			while ((lastIndex = text.indexOf(searchstr, lastIndex + 1)) != -1) {
				component.getHighlighter().addHighlight(
					lastIndex,
					lastIndex + searchstr.length(),
					painter);
			}
		}
		catch (Exception ex) {
			// ...
		}
	}
 
	static void removeBorderFromButton(JButton button) {
		button.setOpaque(false);
		button.setContentAreaFilled(false);
		button.setBorder(new EmptyBorder(2, 2, 2, 2));
	}

	public void requestFocus() {
		search.requestFocus();		
	}

	public void clear() {
		component.getHighlighter().removeAllHighlights();
		index = 0;
		status.setText("");
	}

	public SearchPanel(JTextComponent component, Color highlight) {
		this.component = component;
		this.highlight = highlight;

		setLayout(new BorderLayout());
		setBorder(new EmptyBorder(1, 1, 1, 1));

		/* init the buttons */

		JButton previous = new JButton("<");
		previous.setActionCommand("<");

		JButton next     = new JButton(">");
		next.setActionCommand(">");

		removeBorderFromButton(previous);
		removeBorderFromButton(next);

		previous.addActionListener(this);
		next.addActionListener(this);

		JPanel buttons = new JPanel();
		buttons.setLayout(new GridLayout(1, 2));

		buttons.add(previous);
		buttons.add(next);

		/* init the search field */

		search = new JTextField(15);
		search.addActionListener(this);

		add(search, BorderLayout.WEST);

		/* holder */

		JPanel holder = new JPanel();
		holder.setLayout(new FlowLayout());

		holder.add(new JLabel("Find: "));
		holder.add(search);
		holder.add(buttons);

		add(holder, BorderLayout.WEST);

		/* label for count information */

		status = new JLabel("");
		add(status, BorderLayout.CENTER);
	}
}
