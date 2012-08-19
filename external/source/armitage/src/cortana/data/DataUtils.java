package cortana.data;

import sleep.runtime.*;
import java.util.*;

public class DataUtils {
	/* calculate the difference between two sets */
	public static Set difference(Set a, Set b) {
		Set temp = new HashSet();
		temp.addAll(a);
		temp.removeAll(b);
		return temp;
	}

	/* calculate the intersection of two sets */
	public static Set intersection(Set a, Set b) {
		Set temp = new HashSet();
		temp.addAll(a);
		temp.retainAll(b);
		return temp;
	}
}
