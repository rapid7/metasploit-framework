package ui;

import java.awt.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.*;
import javax.swing.event.*;
import javax.swing.filechooser.*;
import table.*;
import java.util.*;

public class ATable extends JTable {
	public static final String indicator = " \u271A";

	protected boolean alternateBackground = false;

	protected int[] selected = null;

	/* call this function to store selections */
	public void markSelections() {
		selected = getSelectedRows();
	}

	public void fixSelection() {
		if (selected.length == 0)
			return;

		getSelectionModel().setValueIsAdjusting(true);

		int rowcount = getModel().getRowCount();

		for (int x = 0; x < selected.length; x++) {
			if (selected[x] < rowcount) {
				getSelectionModel().addSelectionInterval(selected[x], selected[x]);
			}
		}

		getSelectionModel().setValueIsAdjusting(false);
	}

	/* call this function to restore selections after a table update */
	public void restoreSelections() {
		if (!SwingUtilities.isEventDispatchThread()) {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					fixSelection();
				}
			});
		}
		else {
			fixSelection();
		}
	}

	public static TableCellRenderer getDefaultTableRenderer(final JTable table, final TableModel model) {
		final Set specialitems = new HashSet();
		specialitems.add("Wordlist");
		specialitems.add("PAYLOAD");
		specialitems.add("RHOST");
		specialitems.add("RHOSTS");
		specialitems.add("Template");
		specialitems.add("DICTIONARY");
		specialitems.add("NAMELIST");
		specialitems.add("SigningKey");
		specialitems.add("SigningCert");
		specialitems.add("WORDLIST");
		specialitems.add("SESSION");
		specialitems.add("REXE");
		specialitems.add("EXE::Custom");
		specialitems.add("EXE::Template");
		specialitems.add("USERNAME");
		specialitems.add("PASSWORD");
		specialitems.add("SMBUser");
		specialitems.add("SMBPass");

		return new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)  {
				TableCellRenderer render = table.getDefaultRenderer(String.class);
				String content = (value != null ? value : "") + "";

				if (specialitems.contains(content) || content.indexOf("FILE")!= -1) {
					content = content + indicator;
				}

				JComponent c = (JComponent)render.getTableCellRendererComponent(table, content, isSelected, false, row, column);
				c.setToolTipText(((GenericTableModel)model).getValueAtColumn(table,  row, "Tooltip") + "");

				return c;
			}
		};
	}

	public static TableCellRenderer getFileTypeTableRenderer() {
		return new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)  {
				TableCellRenderer render = table.getDefaultRenderer(String.class);
				JComponent c = (JComponent)render.getTableCellRendererComponent(table, "", isSelected, false, row, column);

				if ("dir".equals(value)) {
					FileSystemView view = FileSystemView.getFileSystemView();
					Icon chooser = view.getSystemIcon(view.getDefaultDirectory());
					((JLabel)c).setIcon(chooser);
				}
				else {
					((JLabel)c).setIcon(null);
				}
				return c;
			}
		};
	}

	public static TableCellRenderer getSimpleTableRenderer() {
		return new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)  {
				TableCellRenderer render = table.getDefaultRenderer(String.class);
				JComponent c = (JComponent)render.getTableCellRendererComponent(table, value, isSelected, false, row, column);
				((JLabel)c).setIcon(null);
				return c;
			}
		};
	}

	public static TableCellRenderer getSizeTableRenderer() {
		return new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)  {
				TableCellRenderer render = table.getDefaultRenderer(String.class);

				JComponent c = (JComponent)render.getTableCellRendererComponent(table, "", isSelected, false, row, column);

				try {
					long size = Long.parseLong(value + "");
					String units = "b";

					if (size > 1024) {
						size = size / 1024;
						units = "kb";
					}

					if (size > 1024) {
						size = size / 1024;
						units = "mb";
					}

					if (size > 1024) {
						size = size / 1024;
						units = "gb";
					}

					((JLabel)c).setText(size + units);
				}
				catch (Exception ex) {

				}

				return c;
			}
		};
	}

	public static TableCellRenderer getTimeTableRenderer() {
		return new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)  {
				TableCellRenderer render = table.getDefaultRenderer(String.class);

				JComponent c = (JComponent)render.getTableCellRendererComponent(table, "", isSelected, false, row, column);

				try {
					long size = Long.parseLong(value + "");
					String units = "ms";

					if (size > 1000) {
						size = size / 1000;
						units = "s";
					}
					else {
						((JLabel)c).setText(size + units);
						return c;
					}

					if (size > 60) {
						size = size / 60;
						units = "m";
					}

					if (size > 60) {
						size = size / 60;
						units = "h";
					}

					((JLabel)c).setText(size + units);
				}
				catch (Exception ex) {

				}

				return c;
			}
		};
	}

	public void adjust() {
		setShowGrid(false);
		setIntercellSpacing(new Dimension(0, 0));
		setRowHeight(getRowHeight() + 2);

		final TableCellEditor defaulte = getDefaultEditor(Object.class);
		setDefaultEditor(Object.class, new TableCellEditor() {
			public Component getTableCellEditorComponent(JTable table, Object value, boolean selected, int row, int col) {
				Component editor = defaulte.getTableCellEditorComponent(table, value, selected, row, col);
				if (editor instanceof JTextComponent)
					new CutCopyPastePopup((JTextComponent)editor);

				return editor;
			}

			public void addCellEditorListener(CellEditorListener l) {
				defaulte.addCellEditorListener(l);
			}

			public void cancelCellEditing() {
				defaulte.cancelCellEditing();
			}

			public Object getCellEditorValue() {
				return defaulte.getCellEditorValue();
			}

			public boolean isCellEditable(EventObject anEvent) {
				return defaulte.isCellEditable(anEvent);
			}

			public void removeCellEditorListener(CellEditorListener l) {
				defaulte.removeCellEditorListener(l);
			}

			public boolean shouldSelectCell(EventObject anEvent) {
				return defaulte.shouldSelectCell(anEvent);
			}

			public boolean stopCellEditing() {
				return defaulte.stopCellEditing();
			}
		});

		final TableCellRenderer defaultr = getDefaultRenderer(Object.class);
		setDefaultRenderer(Object.class, new TableCellRenderer() {
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)  {
				if (value == null) {
					value = "";
				}
				return defaultr.getTableCellRendererComponent(table, value, isSelected, false, row, column);
			}
		});
	}

	public ATable() {
		super();
		adjust();
	}

	public ATable(TableModel model) {
		super(model);
		adjust();
	}

	public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
		alternateBackground = row % 2 == 0;
		Component component = super.prepareRenderer(renderer, row, column);
		//((JComponent)component).setBorder(BorderFactory.createEmptyBorder(120, 80, 120, 80));

		if (!Color.WHITE.equals(component.getForeground())) {
			((JComponent)component).setOpaque(true);
			component.setBackground(getComponentBackground());
		}
		return component;
	}

	public Color getComponentBackground() {
		return alternateBackground ? new Color(0xF2F2F2) : Color.WHITE;
	}
}
