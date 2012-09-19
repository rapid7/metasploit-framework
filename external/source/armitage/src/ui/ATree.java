package ui;

import java.awt.*;
import javax.swing.*;
import javax.swing.tree.*;
import java.util.*;

public class ATree extends JTree {
	public ATree(TreeNode root) {
		super(root);
	}

	public boolean getScrollableTracksViewportWidth() {
		return true;
	}
}
