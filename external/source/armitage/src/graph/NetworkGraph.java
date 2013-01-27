package graph;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;

import java.awt.*;
import java.awt.event.*;

import java.util.*;

import com.mxgraph.swing.*;
import com.mxgraph.view.*;
import com.mxgraph.model.*;
import com.mxgraph.layout.*;
import com.mxgraph.swing.util.*;
import com.mxgraph.swing.handler.*;
import com.mxgraph.swing.view.*;
import com.mxgraph.util.*;

import java.awt.image.*;

public class NetworkGraph extends JComponent implements ActionListener {
	protected mxGraph graph;
	protected mxGraphComponent component;
	protected Object parent;
	protected Properties display;
	protected boolean isAlive = true;
	protected String layout = null;

	/** this component listens for an actionevent from the GUI to tell it when the graph is no longer visible */
	public void actionPerformed(ActionEvent ev) {
		isAlive = false;
	}

	/** returns true if this graph is still in a tab, false otherwise */
	public boolean isAlive() {
		return isAlive;
	}

	/* keeps track of the nodes and their images */
	protected Map nodeImages = new HashMap();

	private class NetworkGraphCanvas extends mxInteractiveCanvas {
		public Image loadImage(String image) {
			if (nodeImages.containsKey(image)) {
				return (Image)nodeImages.get(image);
			}

			return super.loadImage(image);
		}
	}

	/* this class exists so we can create a canvas that lets us add our own image loading handler */
	private class NetworkGraphComponent extends mxGraphComponent {
		public NetworkGraphComponent(mxGraph graph) {
			super(graph);
			setBorder(BorderFactory.createEmptyBorder());
			getHorizontalScrollBar().setUnitIncrement(15);
			getHorizontalScrollBar().setBlockIncrement(60);
			getVerticalScrollBar().setUnitIncrement(15);
			getVerticalScrollBar().setBlockIncrement(60);
		}

		public void paint(Graphics g) {
			Graphics2D g2 = (Graphics2D)g;
			g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION,RenderingHints.VALUE_INTERPOLATION_BICUBIC);
			g2.setRenderingHint(RenderingHints.KEY_RENDERING,RenderingHints.VALUE_RENDER_QUALITY);
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
			super.paint(g2);
		}

		public mxInteractiveCanvas createCanvas() {
			return new NetworkGraphCanvas();
		}
	}

	/** a popup menu for the graph */
	protected GraphPopup popup = null;

	public GraphPopup getGraphPopup() {
		return popup;
	}

	public void setGraphPopup(GraphPopup popup) {
		this.popup = popup;
	}

	public NetworkGraph() {
		this(new Properties());
	}

	public Image getScreenshot() {
		LinkedList cells = new LinkedList();

		/* add the edges to our list of cells to render */
		Iterator i = nodes.values().iterator();
		while (i.hasNext()) {
			Object node = i.next();
			cells.addAll(Arrays.asList(graph.getEdges(node)));
		}

		/* collect all of the nodes */
		cells.addAll(nodes.values());

		/* render the cells y0 */
		return mxCellRenderer.createBufferedImage(
			graph,
			cells.toArray(),
			zoom,
			null,
			true,
			null,
			new NetworkGraphCanvas());
	}

	public void setTransferHandler(TransferHandler h) {
		component.setTransferHandler(h);
	}

	public void clearSelection() {
		graph.clearSelection();
	}

	public void selectAll() {
		graph.selectAll();
	}

	public NetworkGraph(Properties display) {

		/* update a few global properties */
		mxConstants.VERTEX_SELECTION_COLOR = Color.decode(display.getProperty("graph.selection.color", "#00ff00"));
		mxConstants.EDGE_SELECTION_COLOR = Color.decode(display.getProperty("graph.edge.color", "#3c6318"));

		/* on with the show */

		this.display = display;

		graph = new mxGraph() {
			public String getToolTipForCell(Object cell) {
				if (tooltips.get(cell) == null) {
					return "";
				}
				return tooltips.get(cell) + "";
			}
		};
		graph.setAutoOrigin(true);
		graph.setCellsEditable(false);
		graph.setCellsResizable(false);
		graph.setCellsBendable(false);
		graph.setAllowDanglingEdges(false);
		graph.setSplitEnabled(false);
		graph.setKeepEdgesInForeground(false);
		graph.setKeepEdgesInBackground(true);

		parent = graph.getDefaultParent();

		/* create the component... */
		component = new NetworkGraphComponent(graph);
		component.setFoldingEnabled(true);
		component.setConnectable(false);
		component.setCenterPage(true);
		component.setToolTips(true);

		graph.setDropEnabled(true);

		/* enable the rubber band selection non-sense */
		new mxRubberband(component);

		/* setup the mouse listener */
		addPopupListener();

		/* set the background of the component */
		component.getViewport().setOpaque(false);
		component.setOpaque(true);
		component.setBackground(Color.decode(display.getProperty("graph.background.color", "#111111")));

		/* add the graph component to this object */
		setLayout(new BorderLayout());
		add(component, BorderLayout.CENTER);

		/* setup the keyboard shortcuts */
		setupShortcuts();
	}


        public void addActionForKeyStroke(KeyStroke key, Action action) {
                component.getActionMap().put(key.toString(), action);
                component.getInputMap().put(key, key.toString());
        }

        public void addActionForKey(String key, Action action) {
                addActionForKeyStroke(KeyStroke.getKeyStroke(key), action);
        }

        public void addActionForKeySetting(String key, String dvalue, Action action) {
                KeyStroke temp = KeyStroke.getKeyStroke(display.getProperty(key, dvalue));
                if (temp != null) {
                        addActionForKeyStroke(temp, action);
                }
        }

	public void doStackLayout() {
		if (this.layout != null)
			this.layout = "stack";

		mxGraphLayout layout = new mxStackLayout(graph, true, 25);
		layout.execute(parent);
	}

	public void doHierarchicalLayout() {
		if (this.layout != null)
			this.layout = "hierarchical";

		mxGraphLayout layout = new com.mxgraph.layout.hierarchical.mxHierarchicalLayout(graph);
		layout.execute(parent);
	}

	public void doCircleLayout() {
		if (this.layout != null)
			this.layout = "circle";

		CircleLayout layout = new CircleLayout(graph, 100.0);
		layout.execute(parent, getWidth(), getHeight(), zoom);
	}

	public void doTreeLayout() {
		mxGraphLayout layout = new mxFastOrganicLayout(graph);
		layout.execute(parent);
	}

	private void setupShortcuts() {
		addActionForKeySetting("graph.clear_selection.shortcut", "pressed ESCAPE", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				clearSelection();
			}
		});

		addActionForKeySetting("graph.select_all.shortcut", "ctrl pressed A", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				selectAll();
			}
		});

		addActionForKeySetting("graph.zoom_in.shortcut", "ctrl pressed EQUALS", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				zoom(0.10);
			}
		});

		addActionForKeySetting("graph.zoom_out.shortcut", "ctrl pressed MINUS", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				zoom(-0.10);
			}
		});

		addActionForKeySetting("graph.zoom_reset.shortcut", "ctrl pressed 0", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				resetZoom();
			}
		});

		addActionForKeySetting("graph.arrange_icons_stack.shortcut", "ctrl pressed S", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				doStackLayout();
			}
		});

		addActionForKeySetting("graph.arrange_icons_circle.shortcut", "ctrl pressed C", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				doCircleLayout();
			}
		});

		addActionForKeySetting("graph.arrange_icons_hierarchical.shortcut", "ctrl pressed H", new AbstractAction() {
			public void actionPerformed(ActionEvent ev) {
				doHierarchicalLayout();
			}
		});
	}

	public String getCellAt(Point p) {
		Point q = component.getViewport().getViewPosition();
		Point z = new Point((int)(p.getX() + q.getX()), (int)(p.getY() + q.getY()));

		mxCell cell = (mxCell)component.getCellAt((int)z.getX(), (int)z.getY());
		if (cell != null)
			return cell.getId();
		return null;
	}

	public String[] getSelectedHosts() {
		mxCell cell;
		java.util.List sel = new LinkedList();

		Object[] cells = graph.getSelectionCells();

		for (int y = 0; y < cells.length; y++) {
			cell = (mxCell)cells[y];
			if (nodes.containsKey(cell.getId()))
				sel.add(cell.getId());
		}

		String[] selected = new String[sel.size()];
		Iterator i = sel.iterator();
		for (int x = 0; i.hasNext(); x++) {
			selected[x] = i.next() + "";
		}

		return selected;
	}

	private void addPopupListener() {
		component.getGraphControl().addMouseListener(new MouseAdapter() {
			public void handleEvent(MouseEvent ev) {
				if (ev.isPopupTrigger() && getGraphPopup() != null) {
					getGraphPopup().showGraphPopup(getSelectedHosts(), ev);
					ev.consume();
				}
			}

			public void mousePressed(MouseEvent ev) {
				handleEvent(ev);
			}

			public void mouseReleased(MouseEvent ev) {
				handleEvent(ev);
			}

			public void mouseClicked(MouseEvent ev) {
				handleEvent(ev);
			}
		});
	}

	protected double zoom = 1.0;

	public void resetZoom() {
		zoom = 1.0;
		zoom(0.0);
	}

	public void zoom(double factor) {
		zoom += factor;
		component.zoomTo(zoom, true);
	}

	public void start() {
		graph.getModel().beginUpdate();
		nodes.startUpdates();
	}

	public void setAutoLayout(String layout) {
		this.layout = layout;
		autoLayout();
	}

	public void autoLayout() {
		if (layout == null)
			return;

		if (layout.equals("circle"))
			doCircleLayout();

		if (layout.equals("stack"))
			doStackLayout();

		if (layout.equals("hierarchical"))
			doHierarchicalLayout();
	}

	public void end() {
		graph.getModel().endUpdate();

		if (SwingUtilities.isEventDispatchThread()) {
			autoLayout();
			graph.refresh();
		}
		else {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					autoLayout();
					graph.refresh();
				}
			});
		}
	}

	/** delete nodes from this graph */
	public void deleteNodes(String[] ids) {
		Object[] cells = new Object[ids.length];
		for (int x = 0; x < ids.length; x++) {
			cells[x] = nodes.remove(ids[x]);
		}
		graph.removeCells(cells, true);
	}

	/** delete all nodes that were not "touched" since start() was last called */
	public void deleteNodes() {
		java.util.List untouched = nodes.clearUntouched();
		Object[] cells = new Object[untouched.size()];

		Iterator i = untouched.iterator();
		for (int x = 0; i.hasNext(); x++) {
			Map.Entry entry = (Map.Entry)i.next();
			cells[x] = entry.getValue();
		}
		graph.removeCells(cells, true);
	}

	protected TouchMap nodes = new TouchMap();
	protected LinkedList edges = new LinkedList();

	/** highlight a route (maybe to show it's in use...) */
	public void highlightRoute(String src, String dst) {
		Object[] cells = graph.getEdgesBetween(nodes.get(src), nodes.get(dst), true);
		if (cells.length == 0)
			return;

		((mxCell)cells[0]).setStyle("strokeColor=" + display.getProperty("graph.edge_highlight.color", "#00ff00") + ";strokeWidth=4");
	}

	/** show the meterpreter routes . :) */
	public void setRoutes(Route[] routes) {
		/* clear the existing edges... */
		Iterator ij = edges.iterator();
		while (ij.hasNext()) {
			mxCell cell = (mxCell)ij.next();
			graph.getModel().remove(cell);
		}

		edges = new LinkedList();

		/* start updating the graph with our new shtuff */
		Iterator i = nodes.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry temp = (Map.Entry)i.next();

			for (int x = 0; x < routes.length; x++) {
				mxCell start = (mxCell)nodes.get(routes[x].getGateway());

				if ( start != null && !temp.getKey().equals(routes[x].getGateway()) ) {
					if ( routes[x].shouldRoute((String)temp.getKey()) ) {
						mxCell node = (mxCell)temp.getValue();
						mxCell edge = (mxCell)graph.insertEdge(parent, null, "", start, node);
						edge.setStyle("strokeColor=" + display.getProperty("graph.edge.color", "#3c6318") + ";strokeWidth=4");
						edges.add(edge);
					}
				}
			}
		}
	}

	protected Map tooltips = new HashMap();

	public Object addNode(String id, String label, String description, Image image, String tooltip) {
		nodeImages.put(id, image);

		if (label.length() > 0) {
			if (description.length() > 0) {
				description += "\n" + label;
			}
			else {
				description = label;
			}
		}

		mxCell cell;
		if (!nodes.containsKey(id)) {
			cell = (mxCell)graph.insertVertex(parent, id, description, 0, 0, 125, 97);
			nodes.put(id, cell);
		}
		else {
			cell = (mxCell)nodes.get(id);
			cell.setValue(description);
		}
		nodes.touch(id);

		/* set the tooltip for the cell */

		tooltips.put(cell, tooltip);

		/* create the style for this node based on the properties object */

		StringBuffer style = new StringBuffer();
		style.append("shape=image;image=" + id + ";");
		style.append("fontColor=" + display.getProperty("graph.foreground.color", "#cccccc") + ";");

		Font font = Font.decode(display.getProperty("graph.font.font", "Monospaced BOLD 14"));
		style.append("fontSize=" + font.getSize() + ";");
		style.append("fontFamily=" + font.getFamily() + ";");
		style.append("fontStyle=" + font.getStyle() + ";");

		style.append("verticalLabelPosition=bottom;verticalAlign=top");

		cell.setStyle(style.toString());

		return cell;
	}

        public boolean requestFocusInWindow() {
                return component.requestFocusInWindow();
        }
}
