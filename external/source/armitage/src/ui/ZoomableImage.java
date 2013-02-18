package ui;

import javax.swing.*;
import java.awt.*;
import java.awt.image.*;
import java.awt.event.*;
import java.util.*;

public class ZoomableImage extends JLabel {
	protected Icon original = null;
	protected double zoom = 1.0;

	private JMenuItem zoomMenu(String label, final double level) {
		JMenuItem i = new JMenuItem(label);
		i.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				zoom = level;
				updateIcon();
			}
		});
		return i;
	}

	public ZoomableImage() {
		super();

		final JPopupMenu menu = new JPopupMenu();
		menu.add(zoomMenu("25%", 0.25));
		menu.add(zoomMenu("50%", 0.50));
		menu.add(zoomMenu("75%", 0.75));
		menu.add(zoomMenu("100%", 1.0));
		menu.add(zoomMenu("125%", 1.25));
		menu.add(zoomMenu("150%", 1.5));
		menu.add(zoomMenu("200%", 2.0));
		menu.add(zoomMenu("250%", 2.5));

		addMouseListener(new MouseAdapter() {
			public void check(MouseEvent ev) {
				if (ev.isPopupTrigger()) {
					menu.show((JComponent)ev.getSource(), ev.getX(), ev.getY());
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

		setHorizontalAlignment(SwingConstants.CENTER);
	}

	protected void updateIcon() {
		super.setIcon(resizeImage((ImageIcon)original));
	}

	public void setIcon(Icon image) {
		original = image;
		updateIcon();
	}

	protected Icon resizeImage(ImageIcon image) {
		if (zoom == 1.0 || image == null) {
			return image;
		}

		int width = image.getIconWidth();
		int height = image.getIconHeight();

		BufferedImage buffer = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics g = buffer.createGraphics();
		g.drawImage(image.getImage(), 0, 0, width, height, null);
		g.dispose();
		return new ImageIcon(buffer.getScaledInstance( (int)(width * zoom), (int)(height * zoom), Image.SCALE_SMOOTH));
	}
}
