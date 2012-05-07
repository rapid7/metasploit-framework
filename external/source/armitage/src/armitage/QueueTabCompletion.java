package armitage;

import console.Console;
import java.util.*;

/* uses a console queue as a tab completion source */
public class QueueTabCompletion extends GenericTabCompletion {
	protected ConsoleQueue queue;

	public QueueTabCompletion(Console window, ConsoleQueue queue) {
		super(window);
		this.queue = queue;
	}

	public Collection getOptions(String text) {
		return queue.tabComplete(text);
	}
}
