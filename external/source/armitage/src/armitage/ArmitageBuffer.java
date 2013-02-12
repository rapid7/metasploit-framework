package armitage;

import java.util.*;

/*
 * Implement a thread safe store that any client may write to and
 * any client may read from (keeping track of their cursor into
 * the console)
 */
public class ArmitageBuffer {
	private static final class Message {
		public String  message = null;
		public Message next    = null;
	}

	/* store our messages... */
	public Message first  = null;
	public Message last   = null;
	public long    size   = 0;
	public long    max    = 0;
	public String  prompt = "";

	/* store indices into this buffer */
	public Map  indices  = new HashMap();

	/* setup the buffer?!? :) */
	public ArmitageBuffer(long max) {
		this.max = max;
	}

	/* store a prompt with this buffer... we're not going to do any indexing magic for now */
	public String getPrompt() {
		synchronized (this) {
			return prompt;
		}
	}

	/* set the prompt */
	public void setPrompt(String text) {
		synchronized (this) {
			prompt = text;
		}
	}

	/* post a message to this buffer */
	public void put(String text) {
		synchronized (this) {
			/* create our message */
			Message m = new Message();
			m.message = text;

			/* store our message */
			if (last == null && first == null) {
				first = m;
				last = m;
			}
			else {
				last.next = m;
				last = m;
			}

			/* increment number of stored messages */
			size += 1;

			/* limit the total number of past messages to the max size */
			if (size > max) {
				first = first.next;
			}
		}
	}

	/* retrieve a set of all clients consuming this buffer */
	public Collection clients() {
		synchronized (this) {
			LinkedList clients = new LinkedList(indices.keySet());
			return clients;
		}
	}

	/* free a client */
	public void free(String id) {
		synchronized (this) {
			indices.remove(id);
		}
	}

	/* reset our indices too */
	public void reset() {
		synchronized (this) {
			first = null;
			last = null;
			indices.clear();
			size = 0;
		}
	}

	/* retrieve all messages available to the client (if any) */
	public String get(String id) {
		synchronized (this) {
			/* nadaz */
			if (first == null)
				return "";

			/* get our index into the buffer */
			Message index = null;
			if (!indices.containsKey(id)) {
				index = first;
			}
			else {
				index = (Message)indices.get(id);

				/* nothing happening */
				if (index.next == null)
					return "";

				index = index.next;
			}

			/* now let's walk through it */
			StringBuffer result = new StringBuffer();
			Message temp = index;
			while (temp != null) {
				result.append(temp.message);
				index = temp;
				temp = temp.next;
			}

			/* store our index */
			indices.put(id, index);

			return result.toString();
		}
	}

	public String toString() {
		return "[" + size + " messages]";
	}
}
