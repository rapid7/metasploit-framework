package msf;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import javax.net.*;

import java.security.*;
import java.security.cert.*;

/* taken from jIRCii, I developed it, so I get to do what I want ;) */
public class SecureSocket
{
    protected SSLSocket socket;

    public SecureSocket(String host, int port) throws Exception
    {
       socket = null;

       DummySSLSocketFactory factory = new DummySSLSocketFactory();
       socket = (SSLSocket)factory.createSocket(host, port);

       socket.setSoTimeout(8192);
       socket.startHandshake();   
    }

    public Socket getSocket()
    {
       return socket;
    }

    private static class DummySSLSocketFactory extends SSLSocketFactory 
    {
       private SSLSocketFactory factory;

       public DummySSLSocketFactory() 
       {
          try 
          {
              SSLContext sslcontext = SSLContext.getInstance("SSL");
              sslcontext.init(null, new TrustManager[] {new DummyTrustManager()}, new java.security.SecureRandom());
              factory = (SSLSocketFactory) sslcontext.getSocketFactory();
          } 
          catch(Exception ex) 
          {
              ex.printStackTrace();
          }
       }

       public static SocketFactory getDefault() 
       {
          return new DummySSLSocketFactory();
       }

       public Socket createSocket(Socket socket, String s, int i, boolean flag) throws IOException 
       {
          return factory.createSocket(socket, s, i, flag);
       }

       public Socket createSocket(InetAddress inaddr, int i, InetAddress inaddr1, int j) throws IOException 
       {
          return factory.createSocket(inaddr, i, inaddr1, j);
       }

       public Socket createSocket(InetAddress inaddr, int i) throws IOException 
       {
          return factory.createSocket(inaddr, i);
       }

       public Socket createSocket(String s, int i, InetAddress inaddr, int j) throws IOException 
       {
          return factory.createSocket(s, i, inaddr, j);
       }

       public Socket createSocket(String s, int i) throws IOException 
       {
          return factory.createSocket(s, i);
       }

       public String[] getDefaultCipherSuites() 
       {
          return factory.getSupportedCipherSuites();
       }

       public String[] getSupportedCipherSuites() 
       {
          return factory.getSupportedCipherSuites();
       }
   }

   private static class DummyTrustManager implements X509TrustManager 
   {
       public void checkClientTrusted(X509Certificate ax509certificate[], String authType) 
       {
           return;
       }

       public void checkServerTrusted(X509Certificate ax509certificate[], String authType) 
       {
           return;
       }
                
       public boolean isClientTrusted(X509Certificate[] cert) 
       {
           return true;
       }

       public boolean isServerTrusted(X509Certificate[] cert) 
       {
           return true;
       }

       public X509Certificate[] getAcceptedIssuers() 
       {
           return new X509Certificate[0];
       }
   }
}

