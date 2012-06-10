package ui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import java.awt.datatransfer.*;
import java.awt.dnd.*;
import javax.swing.tree.*;

public class ModuleTransferHandler extends TransferHandler {
	public int getSourceActions(JComponent c) {
		return COPY_OR_MOVE;
	}

	public Transferable createTransferable(JComponent c) {
		if (c instanceof JTree) {
			JTree temp = (JTree)c;
			TreePath path = temp.getSelectionPath();

			if (path != null) {
				StringBuffer pathz = new StringBuffer();
				Object o[] = path.getPath();
				for (int x = 1; x < o.length; x++) {
					pathz.append(o[x] + "");

					if ((x + 1) < o.length)
						pathz.append("/");
				}

				return new StringSelection(pathz + "");
			}
		}
		return null;
	}

	public void exportDone(JComponent c, Transferable t, int action) {
	}

	public boolean canImport(TransferHandler.TransferSupport blah) {
		if (blah.getComponent() instanceof JTree) {
			return false;
		}
		return true;
	}

	public interface ModuleTransferListener {
		public void completeTransfer(String text, Point location);
	}

	protected ModuleTransferListener completeJob = null;
	public void setHandler(ModuleTransferListener l) {
		completeJob = l;
	}

	public boolean importData(TransferHandler.TransferSupport blah) {
		try {
			Point  coords = blah.getDropLocation().getDropPoint();
			String text   = blah.getTransferable().getTransferData(DataFlavor.stringFlavor) + "";
			if (completeJob != null)
				completeJob.completeTransfer(text, coords);
		}
		catch (Exception ex) {

		}
		return true;
	}
}
