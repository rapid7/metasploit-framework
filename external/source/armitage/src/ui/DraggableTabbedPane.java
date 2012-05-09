package ui;

import java.awt.Component;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.awt.image.BufferedImage;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JTabbedPane;

/*
 * Adapted from: http://stackoverflow.com/questions/60269/how-to-implement-draggable-tab-using-java-swing
 * Original author: Tom Martin
 * StackOverflow.com contents is Creative Commons Share-Alike (Attribution Required) license
 *
 * Thanks Tom for the excellent example.
 */
public class DraggableTabbedPane extends JTabbedPane {

	private boolean dragging = false;
	private Image tabImage = null;
	private Point currentMouseLocation = null;
	private int draggedTabIndex = 0;

	public DraggableTabbedPane() {
		super();
		addMouseMotionListener(new MouseMotionAdapter() {
			public void mouseDragged(MouseEvent e) {
				if(!dragging) {
					// Gets the tab index based on the mouse position
					int tabNumber = getUI().tabForCoordinate(DraggableTabbedPane.this, e.getX(), e.getY());

					if(tabNumber >= 0) {
						draggedTabIndex = tabNumber;
						Rectangle bounds = getUI().getTabBounds(DraggableTabbedPane.this, tabNumber);

						// Paint the tabbed pane to a buffer
						Image totalImage = new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_INT_ARGB);
						Graphics totalGraphics = totalImage.getGraphics();
						totalGraphics.setClip(bounds);

						// Don't be double buffered when painting to a static image.
						setDoubleBuffered(false);
						paint(totalGraphics);

						// Paint just the dragged tab to the buffer
						tabImage = new BufferedImage(bounds.width, bounds.height, BufferedImage.TYPE_INT_ARGB);
						Graphics graphics = tabImage.getGraphics();
						graphics.drawImage(totalImage, 0, 0, bounds.width, bounds.height, bounds.x, bounds.y, bounds.x + bounds.width, bounds.y+bounds.height, DraggableTabbedPane.this);

						dragging = true;
						repaint();

						graphics.dispose();
						totalGraphics.dispose();
					}
				}
				else {
					currentMouseLocation = e.getPoint();

					// Need to repaint
					repaint();
				}

				super.mouseDragged(e);
			}
		});

		addMouseListener(new MouseAdapter() {
			public void mouseReleased(MouseEvent e) {

				if(dragging) {
					int tabNumber = getUI().tabForCoordinate(DraggableTabbedPane.this, e.getX(), 10);

					if (e.getX() < 0) {
						tabNumber = 0;
					}
					else if (tabNumber == -1) {
						tabNumber = getTabCount() - 1;
					}

					if (tabNumber >= 0) {
						Component comp = getComponentAt(draggedTabIndex);
						Component title = getTabComponentAt(draggedTabIndex);
						removeTabAt(draggedTabIndex);
						insertTab("", null, comp, null, tabNumber);
						setTabComponentAt(tabNumber, title);
						setSelectedIndex(tabNumber);
					}
				}

				dragging = false;
				tabImage = null;
			}
		});
	}

	protected void paintComponent(Graphics g) {
		super.paintComponent(g);

		// Are we dragging?
		if(dragging && currentMouseLocation != null && tabImage != null) {
			// Draw the dragged tab
			g.drawImage(tabImage, currentMouseLocation.x, currentMouseLocation.y, this);
		}
	}
}
