package msfgui;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JOptionPane;

/**
 * Convenient handler for showing popup windows from mouse clicks
 * @author scriptjunkie
 */
public abstract class PopupMouseListener extends MouseAdapter{
		public void mousePressed(MouseEvent e) {
			if (e.isPopupTrigger())
				showPopup(e);
		}
		public void mouseReleased(MouseEvent e) {
			if (e.isPopupTrigger())
				showPopup(e);
		}
		public void mouseClicked(MouseEvent e){ //show interaction window on double-click
			try{
				if(e.getClickCount() == 2)
					doubleClicked(e);
			}catch(MsfException xre){
				JOptionPane.showMessageDialog(null, "action failed " + xre);
			}
		}
		public abstract void doubleClicked (MouseEvent e) throws MsfException;
		public abstract void showPopup(MouseEvent e);
}
