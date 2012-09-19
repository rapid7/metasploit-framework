package graph;

import java.awt.event.MouseEvent;

/** an interface to accept a clicked on word and a mouse event... it's up to the implementor to decide
    what should happen with this magical information */
public interface GraphPopup {
	public void showGraphPopup(String[] nodes, MouseEvent ev);
}
