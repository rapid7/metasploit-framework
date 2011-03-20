package msfgui;

import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;

/**
 * Table customization defaults to non-editable, autosorted table with some preferences
 * from the MsfGuiApp properties set.
 * Also has a more sane column class getter and default renderer.
 *
 * @author scriptjunkie
 */
public class MsfTable extends javax.swing.JTable {
	/**
	 * Default constructor just takes column names
	 * @param colnames The names of the columns in the table
	 */
	public MsfTable(String[] colnames){
		setModel(new javax.swing.table.DefaultTableModel(new Object [][] {}, colnames) {
			public Class getColumnClass(int columnIndex) {
				try{
					return getValueAt(0, columnIndex).getClass();
				}catch(ArrayIndexOutOfBoundsException aioobex){
				}catch(NullPointerException aioobex){
				}
				return java.lang.String.class;
			}
			public boolean isCellEditable(int i,int j) {
				return false;
			}
		});
		setAutoCreateRowSorter(true); //sorting is cool!

		//Render options
		boolean showLines = Boolean.TRUE.equals(MsfguiApp.getPropertiesNode().get("tableShowLines"));
		setShowHorizontalLines(showLines);
		setShowVerticalLines(showLines);
		setDefaultRenderer(java.util.Date.class, new javax.swing.table.DefaultTableCellRenderer());
		if(!"off".equals(MsfguiApp.getPropertiesNode().get("tableResize"))) //
			setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);

		//On double-click show a window with cell contents
		addMouseListener(new MouseAdapter(){
			public void mouseClicked(MouseEvent e){
				if (e.getClickCount() != 2)
					return;
				JTextArea jack = new JTextArea(getValueAt(
						rowAtPoint(e.getPoint()),
						columnAtPoint(e.getPoint())).toString());
				jack.setLineWrap(true);
				JScrollPane scroll = new JScrollPane(jack);
				scroll.setPreferredSize(new Dimension(400, 300));
				scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
				JOptionPane.showMessageDialog(MsfTable.this, scroll,"Cell info",JOptionPane.INFORMATION_MESSAGE);
			}
		} );
	}
}
