package table;

import java.util.*;
import javax.swing.table.*;
import javax.swing.JTable;
import javax.swing.SwingUtilities;

public class GenericTableModel extends AbstractTableModel {
	protected String[] columnNames;
	protected List     rows;
	protected String   leadColumn;
	protected boolean[] editable;
	protected boolean   hidden = false;
	protected List     all;

	public void showHidden(boolean f) {
		synchronized (this) {
			if (f != hidden) {
				if (f) {
					rows = new ArrayList(all.size());
					rows.addAll(all);
				}
				else {
					Iterator i = rows.iterator();
					while (i.hasNext()) {
						Map temp = (Map)(i.next());
						if ("1".equals( temp.get("Hide") ))
							i.remove();
					}
				}
			}
			hidden = f;
		}
	}

	/** this function is *not* thread safe */
	public List getRows() {
		return rows;
	}
	
	public GenericTableModel(String[] columnNames, String leadColumn, int anticipatedSize) {
		this.columnNames = columnNames;
		this.leadColumn  = leadColumn;
		rows = new ArrayList(anticipatedSize);
		all = new ArrayList(anticipatedSize);

		editable = new boolean[columnNames.length];
		for (int x = 0; x < editable.length; x++) {
			editable[x] = false;
		}	
	}

	public void setCellEditable(int column) {
		editable[column] = true;
	}

	public boolean isCellEditable(int row, int column) {
		return editable[column];
	}

	public Object[] getSelectedValues(JTable t) {
		synchronized (this) {
			int row[] = t.getSelectedRows();
			Object[] rv = new Object[row.length];

			for (int x = 0; x < row.length; x++) {
				int r = t.convertRowIndexToModel(row[x]);
				if (r < rows.size() && r >= 0)
					rv[x] = ( (Map)rows.get(r) ).get(leadColumn);
				else
					rv[x] = null;
			}

			return rv;
		}
	}

	public Object[][] getSelectedValuesFromColumns(JTable t, String cols[]) {
		synchronized (this) {
			int row[] = t.getSelectedRows();
			Object[][] rv = new Object[row.length][cols.length];

			for (int x = 0; x < row.length; x++) {
				int r = t.convertRowIndexToModel(row[x]);
				for (int y = 0; y < cols.length; y++) {
					rv[x][y] = ( (Map)rows.get(r) ).get(cols[y]);
				}
			}

			return rv;
		}
	}

	public Object getSelectedValue(JTable t) {
		synchronized (this) {
			Object[] values = getSelectedValues(t);
			if (values.length == 0) 
				return null;

			return values[0];
		}
	}

	public Object getValueAt(JTable t, int row, String column) {
		synchronized (this) {
			row = t.convertRowIndexToModel(row);
			if (row == -1) 
				return null;

			return ( (Map)rows.get(row) ).get(column);
		}
	}

	public int getSelectedRow(JTable t) {
		synchronized (this) {
			return t.convertRowIndexToModel(t.getSelectedRow());
		}
	}

	public void _setValueAtRow(int row, String column, String value) {
		((Map)rows.get(row)).put(column, value);
	}

	public void setValueForKey(String key, String column, String value) {
		int row = -1;

		synchronized (this) {
			Iterator i = rows.iterator();
			for (int x = 0; i.hasNext(); x++) {
				Map temp = (Map)i.next();
				if (key.equals(temp.get(leadColumn))) {
					row = x;
					break;
				}
			}
		}

		if (row != -1)
			setValueAtRow(row, column, value);
	}

	public void setValueAtRow(final int row, final String column, final String value) {
		if (SwingUtilities.isEventDispatchThread())
			_setValueAtRow(row, column, value);
		else 
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_setValueAtRow(row, column, value);
				}
			});
	}

	public Object getSelectedValueFromColumn(JTable t, String column) {
		synchronized (this) {
			int row = t.getSelectedRow();
			if (row == -1)
				return null;

			return getValueAt(t, row, column);
		}
	}

	public String getColumnName(int x) {
		return columnNames[x];
	}

	public int getColumnCount() {
		return columnNames.length;
	}

	public void addEntry(final Map row) {
		if (SwingUtilities.isEventDispatchThread())
			_addEntry(row);
		else 
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_addEntry(row);
				}
			});
	}

	public void clear(final int newSize) {
		if (SwingUtilities.isEventDispatchThread())
			_clear(newSize);
		else 
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					_clear(newSize);
				}
			});
	}

	public void fireListeners() {
		if (SwingUtilities.isEventDispatchThread())
			fireTableDataChanged();
		else 
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					fireTableDataChanged();
				}
			});
	}
	
	public void _addEntry(Map row) {
		int size;	
		synchronized (this) {
			if (hidden == true || !"1".equals( row.get("Hide") )) {
				rows.add(row);
			}
			all.add(row);
			size = rows.size() - 1;
		}
	}

	public void _clear(int anticipatedSize) {
		synchronized (this) {
			rows = new ArrayList(anticipatedSize);
			all = new ArrayList(anticipatedSize);
		}
	}

	public int getRowCount() {
		synchronized (this) {
			return rows.size();
		}
	}

	public Object getValueAtColumn(JTable t, int row, String col) {
		synchronized (this) {
			row = t.convertRowIndexToModel(row);

			Map temp = (Map)rows.get(row);
			return temp.get(col);
		}
	}

	public Object getValueAt(int row, int col) {
		synchronized (this) {
			if (row < rows.size()) {
				Map temp = (Map)rows.get(row);
				return temp.get(getColumnName(col));
			}
			return null;
		}
	}

	public void setValueAt(Object value, int row, int col) {
		synchronized (this) {
			Map temp = (Map)rows.get(row);
			temp.put(getColumnName(col), value);
		}		
	}
}
