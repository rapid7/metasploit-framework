package msfgui;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.DefaultTableModel;

/**
 * Table customization defaults to non-editable, autosorted table with some preferences
 * from the MsfGuiApp properties set.
 * Also has a more sane column class getter and default renderer.
 *
 * @author scriptjunkie
 */
public class MsfTable extends javax.swing.JTable {
	private final String[] dbNames;
	private final String dbTable;
	public RpcConnection rpcConn;
	/**
	 * Default constructor just takes column names
	 * @param colnames The names of the columns in the table
	 */
	public MsfTable(final RpcConnection rpcConn, String[] colnames, String dbTable, String[] dbNames){
		this.dbNames = dbNames;
		this.dbTable = dbTable;
		this.rpcConn = rpcConn;
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
	/** Automatically query more info on new data */
	public void addAutoAdjuster(final JScrollPane pane){
		//Add autoadjuster to get more DB info
		pane.getVerticalScrollBar().addAdjustmentListener(new AdjustmentListener(){
			public void adjustmentValueChanged(AdjustmentEvent evt) {
				java.awt.Adjustable adj = evt.getAdjustable();
				if(evt.getValueIsAdjusting() || adj.getValue() + adj.getVisibleAmount() != adj.getMaximum())
					return;
				Component source = ((Component)evt.getSource());
				while(!(source instanceof JScrollPane))
					source = source.getParent();
				int rowCount = getRowCount();
				if(rowCount == 0 || (getRowCount() % 100) != 0)
					return;
				reAddQuery(false, rowCount);
			}
		});
	}

	/** Clear a table's contents, reenabling the tab, and replace with contents of data returned from a db call */
	public void reAddQuery(boolean force, int offset) {
		if(!force && !DraggableTabbedPane.isVisible(this))
			return; //Don't re-add if not visible
		try {
			HashMap arg = new HashMap(10);
			arg.put("workspace", MsfguiApp.workspace);
			arg.put("offset", offset);
			List data = (List) ((Map)rpcConn.execute("db."+dbTable, arg)).get(dbTable);
			if(data == null)
				return;
			DefaultTableModel mod = (DefaultTableModel) getModel();
			while (mod.getRowCount() > offset)
				mod.removeRow(mod.getRowCount() - 1);
			for (Object dataObj : data) {
				Object[] row = new Object[dbNames.length];
				for (int i = 0; i < dbNames.length; i++){
					row[i] = ((Map) dataObj).get(dbNames[i]);
					try{
						if(dbNames[i].endsWith("_at") || dbNames[i].equals("time"))
							row[i] = new java.util.Date(Long.parseLong(row[i].toString()) * 1000);
					}catch(NumberFormatException nfex){
						//don't do anything
					}
				}
				mod.addRow(row);
			}
			TableHelper.fitColumnWidths(mod, this);
			DraggableTabbedPane.setTabComponentEnabled(this, true);
		} catch (MsfException mex) {
			mex.printStackTrace();
			if(mex.getMessage().equals("database not loaded"))
				throw mex;
		}
	}
}
