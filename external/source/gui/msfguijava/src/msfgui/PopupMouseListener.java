package msfgui;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JOptionPane;

/**
 *
 * @author scriptjunkie
 */
public abstract class PopupMouseListener extends MouseAdapter{
		public void mousePressed(MouseEvent e) {
			showPopup(e);
		}
		public void mouseReleased(MouseEvent e) {
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
