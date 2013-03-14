package graph;

import java.util.ArrayList;
import java.util.List;

import com.mxgraph.model.mxIGraphModel;
import com.mxgraph.util.mxRectangle;
import com.mxgraph.view.mxGraph;
import com.mxgraph.layout.*;

public class CircleLayout extends mxCircleLayout
{
	public CircleLayout(mxGraph graph, double r) {
		super(graph, r);
	}

	/* override this so it doesn't make the circle so damned big :P */
	public void execute(Object parent, int width, int height, double zoom)
	{
		mxIGraphModel model = graph.getModel();
		model.beginUpdate();
		try
		{
			double max = 0;
			Double top = null;
			Double left = null;
			List<Object> vertices = new ArrayList<Object>();
			int childCount = model.getChildCount(parent);

			for (int i = 0; i < childCount; i++)
			{
				Object cell = model.getChildAt(parent, i);

				if (!isVertexIgnored(cell))
				{
					vertices.add(cell);
					mxRectangle bounds = getVertexBounds(cell);

					if (top == null)
					{
						top = bounds.getY();
					}
					else
					{
						top = Math.min(top, bounds.getY());
					}

					if (left == null)
					{
						left = bounds.getX();
					}
					else
					{
						left = Math.min(left, bounds.getX());
					}

					max = Math.min(max, Math.max(bounds.getWidth(), bounds.getHeight()));
				}
				else if (!isEdgeIgnored(cell))
				{
					if (isResetEdges())
					{
						graph.resetEdge(cell);
					}
	
					if (isDisableEdgeStyle())
					{
						setEdgeStyleEnabled(cell, false);
					}
				}
			}

			int vertexCount = vertices.size();
			double r = (width > height ? height : width) / (2.80 * zoom);

			// Moves the circle to the specified origin
			if (moveCircle)
			{
				top = x0;
				left = y0;
			}

			circle(vertices.toArray(), r, left.doubleValue(), top.doubleValue());
		}
		finally
		{
			model.endUpdate();
		}
	}
}
