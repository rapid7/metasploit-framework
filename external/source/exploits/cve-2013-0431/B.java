import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

public class B
  implements PrivilegedExceptionAction
{
  public B()
  {
    try
    {
      AccessController.doPrivileged(this); } catch (Exception e) {
    }
  }

  public Object run() {
    System.setSecurityManager(null);
    return new Object();
  }
}
