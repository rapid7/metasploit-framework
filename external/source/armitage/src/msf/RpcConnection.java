package msf;

import java.io.*;
import java.net.*;
import java.text.*;
import java.util.*;
import javax.xml.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;

/**
 * This is a modification of msfgui/RpcConnection.java by scriptjunkie. Taken from 
 * the Metasploit Framework Java GUI. 
 */
public interface RpcConnection {
	public Object execute(String methodName) throws IOException;
	public Object execute(String methodName, Object[] params) throws IOException;
}
