import java.sql.*;
import java.util.logging.Logger;
import java.util.Properties;
import java.util.AbstractSet;
import java.util.ServiceLoader;
import java.util.Iterator;


public class FakeDriver extends AbstractSet implements java.sql.Driver
{
    public static final String URL_PREFIX = "jdbc:msf:sql:";
	public static ServiceLoader _s1;
	
    static {
		_s1 = ServiceLoader.load(Object.class);
    }
    
    public Iterator iterator()
    {
		return _s1.iterator();
	}
    
    public FakeDriver() {
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

	//AbstractSet
	public final int size() {
		return 2;
	}
}
