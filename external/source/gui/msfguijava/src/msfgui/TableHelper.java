package msfgui;

import java.awt.Component;
import java.util.Vector;
import javax.swing.JTable;
import javax.swing.table.*;

/**
 * Provides methods to help format tables from data
 * @author scriptjunkie
 */
public class TableHelper {
	public static final int MARGIN = 4;

	/** Sets preferred column widths for the table based on header and data content. */
	public static void fitColumnWidths(TableModel model, JTable mainTable) {
		for (int col = 0; col < model.getColumnCount();col++) {
			TableColumn tc = mainTable.getColumnModel().getColumn(col);
			TableCellRenderer tcr = mainTable.getTableHeader().getDefaultRenderer();
			int width = tcr.getTableCellRendererComponent(mainTable,
					model.getColumnName(col), false, false, 0, col).getPreferredSize().width + MARGIN;
			if(model.getRowCount() > 0)
				tcr = mainTable.getDefaultRenderer(model.getColumnClass(col));
			for (int row = 0; row < model.getRowCount();row++) {
				Component c = tcr.getTableCellRendererComponent(mainTable,
						model.getValueAt(row, col), false, false, row, col);
				if (width < c.getPreferredSize().width + MARGIN)
					width = c.getPreferredSize().width + MARGIN;
			}
			tc.setPreferredWidth(width);
		}
	}

	/** Based on a header row demonstrating the length and position of the fields,
	 * break a line into column elements. */
	protected static Vector fill(String line, String headerRow){
		Vector output = new Vector();
		boolean lastWhitespace = false;
		StringBuilder val = new StringBuilder();
		int max = Math.max(headerRow.length(), line.length());
		for(int i = 0; i < max; i++){
			if(headerRow.length() <= i){
				val.append(line.charAt(i));
				continue;
			}
			if(lastWhitespace && !Character.isWhitespace(headerRow.charAt(i))){
				//If it's a number, make it an integer; otherwise a string
				String cell = val.toString().trim();
				try{
					output.add(Integer.parseInt(cell));
				}catch(NumberFormatException nex){
					output.add(cell);
				}
				val.delete(0, val.length());
			}
			if(line.length() > i)
				val.append(line.charAt(i));
			lastWhitespace = Character.isWhitespace(headerRow.charAt(i));
		}
		//If it's a number, make it an integer; otherwise a string
		String cell = val.toString().trim();
		try{
			output.add(Integer.parseInt(cell));
		}catch(NumberFormatException nex){
			output.add(cell);
		}
		return output;
	}
}
