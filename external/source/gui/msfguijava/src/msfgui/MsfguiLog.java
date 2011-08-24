package msfgui;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * This class keeps a record of activities taken, sessions run, and
 * credentials collected
 * @author scriptjunkie
 */
public class MsfguiLog {
	final protected Map sessions; // maps session ids to sessions
	final protected ArrayList activityLog; // list of strings denoting major activities
	final protected DateFormat formatter;
	public static MsfguiLog defaultLog;

	/** Sets up default log */
	public static void initDefaultLog(){
		defaultLog = new MsfguiLog();
	}

	/** Creates a new log to be written to a file */
	public MsfguiLog() {
		sessions = new HashMap();
		activityLog = new ArrayList();
		formatter = DateFormat.getDateTimeInstance();
		activityLog.add(now()+" msfgui started.");
	}
	/** Ensure that a session is recorded in the sessions map */
	public void logSession(Map session){
		if(sessions.get(session.get("id")) != null)
			return;
		sessions.put(session.get("id"), session);
		activityLog.add(now() + "  Session "+session.get("id")+" to "+session.get("tunnel_peer")+" opened.");
	}
	/** See if any non-console sessions have been closed. */
	public void checkSessions(Map sessionsActive){
		for(Object o : sessions.keySet()){
			Map session = (Map)sessions.get(o);
			//mark as inactive if we haven't already done so, and it is inactive
			if(session.get("inactive") == null && sessionsActive.get(o) == null){
				session.put("inactive", o);
				activityLog.add(now() + " Session "+o+" closed.");
			}
		}
	}
	/** Logs method calls, such as module runs, console commands, and plugin actions */
	public void logMethodCall(String methodName, Object[] params) {
		try {
			if (methodName.startsWith("session.")) {
				if (methodName.endsWith("_write")) 
					logConsole(params[0].toString(), params[1].toString(), true);
				else if (methodName.endsWith("_run_single"))
					logConsole(params[0].toString(), params[1].toString(), true);
				else if (methodName.endsWith("_script"))
					logConsole(params[0].toString(), "run " + params[1].toString(), true);
				else if (methodName.endsWith("_upgrade"))
					activityLog.add(now() + " Session " + params[0] + " upgrade initiated.");
			} else if (methodName.equals("module.execute")) {
				activityLog.add(now() + "  " + params[0] + " " + params[1] + " executed with options " + params[2]);
			} else if (methodName.equals("console.write")) {
				logConsole("Console " + params[0].toString(), params[1].toString(), true);
			} else if (methodName.equals("console.destroy")) {
				activityLog.add(now() + " Console " + params[0] + " destroyed.");
			} else if (methodName.equals("plugin.load")) {
				activityLog.add(now() + " Plugin " + params[0] + " loading.");
			} else if (methodName.equals("plugin.unload")) {
				activityLog.add(now() + " Plugin " + params[0] + " unloaded.");
			} else if (methodName.equals("db.connect")) {
				activityLog.add(now() + " Database connection started with options " + params[0]);
			}
		} catch (MsfException mex) {
		}
	}

	/** Logs received data */
	public void logMethodReturn(String methodName, Object[] params, Object result) {
		try {
			//new consoles are added to the active session list
			if (methodName.equals("console.create")) {
				activityLog.add(now() + " Console " + ((Map) result).get("id") + " created.");
				sessions.put("Console " + ((Map) result).get("id"), result);
				((Map)result).put("inactive", "console"); // mark consoles as inactive to avoid session checking
			} else if (methodName.equals("console.list")) {
				List consoles = ((List)((Map)result).get("consoles"));
				for (Object console : consoles){
					activityLog.add(now() + " Console " + ((Map) console).get("id") + " discovered.");
					sessions.put("Console " + ((Map) console).get("id"), result);
					((Map)console).put("inactive", "console");
				}
			//New data on existing sessions
			} else if (methodName.equals("console.read")) {
				logConsole("Console " + params[0], new String(RpcConnection.getData((Map)result)), false);
			} else if (methodName.startsWith("session.") && methodName.endsWith("_read")) {
				logConsole(params[0].toString(), new String(RpcConnection.getData((Map)result)), false);
			}
		} catch (MsfException mex) {
		}
	}
	/** Record console communication */
	public void logConsole(String sessionId, String message, boolean sending){
		Map session = (Map)sessions.get(sessionId);
		if(session == null || message.length() == 0)
			return;
		//if it is multiline, add a line break before
		if((message.indexOf('\n') - message.length()) % message.length() != -1)
			message = "\n"+message;
		ArrayList consoleLog = (ArrayList)session.get("console");
		if(consoleLog == null){
			consoleLog = new ArrayList(30);
			session.put("console",consoleLog);
		}
		message = htmlEntities(message); // Fix dangerous characters XSS-wise
		if(sending)
			consoleLog.add(now() + " >>>" + message);
		else
			consoleLog.add(now() + " " + message);
	}
	/** Saves the file and returns where */
	public String save() throws IOException{ //example: /tmp/msfguilog_Jun-9-2010.html
		String destination = MsfguiApp.getTempFolder()+File.separator+"msfguilog_"
					+(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM).format(
					new Date()).replaceAll("[, :]+","-"))+".html";
		save(destination);
		return destination;
	}
	public String htmlEntities(String input){
		return input.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
				.replaceAll("\"", "&quot;");
	}
	/** Saves the file and returns where */
	public String save(String filename) throws IOException{
		activityLog.add(now()+" msfgui log created.");
		FileWriter fout = new FileWriter(filename);
		
		//Style header
		fout.write("<html><head><style type=\"text/css\">\n" +
				"pre {font-size:9pt;}\n" +
				"td{font-size:11pt; padding-right: 10px; padding-top: 5px;}\n"+
				"body{ font:13px Arial,Helvetica,sans-serif;}\n" +
				 "h1 {border-bottom: 1px solid #BBBBBB; margin: 10px 0 15px 0;}\n" +
				 "h2 {margin: 0 0 10px 0 ;}\n" +
				 "h1.header  {font-size:3em;\n" +
				 "margin:20px 0 30px;\n" +
				 "text-align:center;}\n" +
				 "tr.sent td {background-color: #EEEEEE; color: black;}\n" +
				 "tr.recv td {background-color: #FFFFFF; color: black;}\n" +
				 "div.session {float: left; padding-right: 10px;}\n" +
				 "#page{margin:0 auto; padding:30px 150px;}\n" +
				"</style></head>\n<body>\n<div id=\"page\"><h1 class=\"header\">msfgui</h1>");
		
		//Host summary
		//Add headers
		fout.write("<h1>Hosts</h1>");
		Set sessionsEntrySet = sessions.entrySet();
		HashMap hosts = new HashMap();
		//Map hosts to sessions by IP
		for(Object e : sessionsEntrySet){
			Map session = (Map)((Entry) e).getValue();
			if(session.containsKey("tunnel_peer")){ //actual session; not console
				String host = session.get("tunnel_peer").toString().split(":")[0];
				Set hostSet = (Set)hosts.get(host);
				if(hostSet == null){
					hostSet = new HashSet();
					hosts.put(host, hostSet);
				}
				hostSet.add(session);
			}
		}
		if(hosts.isEmpty()){
			fout.write("<p>None. Go exploit something next time.</p>");
		}else{
			fout.write("<table><thead><tr><td>host</td>\n");
			ArrayList headers = new ArrayList();
			headers.add("type");
			headers.add("via_exploit");
			headers.add("via_payload");
			headers.add("tunnel_peer");
			headers.add("tunnel_local");
			headers.add("desc");
			fout.write("<td>type</td><td>via exploit</td><td>via payload</td><td>tunnel peer</td><td>tunnel local</td><td>desc</td>");
			fout.write("</tr></thead><tbody>\n");
		
			for(Object e : hosts.entrySet()){
				String key = ((Entry)e).getKey().toString();
				fout.write("<tr><td>"+key+"</td>\n");
				Set hostSessions = (Set)(((Entry)e).getValue());
				for(Object o : hostSessions){
					Map session = (Map)o;
					for(Object var : headers)
						fout.write("<td>"+session.get(var)+"</td>");
					fout.write("</tr>\n<tr><td></td>");
				}
				fout.write("</tr>");
			}
			fout.write("</tbody></table>\n\n");
		}//end hosts
		
		//Activity log
		fout.write("<h1>Activities</h1><table><tbody>\n");
		for(Object o : activityLog)
			fout.write("<tr><td>"+htmlEntities(o.toString())+"</td></tr>\n");
		fout.write("</tbody></table>\n\n");
		
		//Complete console logs
		fout.write("<h1>Session logs</h1>\n");
		for(Object e : sessionsEntrySet){
			Entry ent = (Entry) e;
			Object log = ((Map)(ent.getValue())).get("console");
			if(log == null)
				continue;
			Map session = (Map)ent.getValue();
			fout.write("<div class=\"session\"><h2>Session "+ent.getKey()+"</h2>");
			if(session.containsKey("tunnel_peer"))
				fout.write("To " +	session.get("tunnel_peer"));
			fout.write("<table><tbody>\n");
			for(Object logEntry : (ArrayList)log){
				String entryString = logEntry.toString();

				//If has a newline, and it's not at the end, it's multiline - put in <pre> tags
				if((entryString.indexOf('\n') - entryString.length()) % entryString.length() != -1)
					entryString = "<pre>"+entryString+"</pre>";
				if(entryString.contains(">>>"))
					fout.write("<tr class=\"sent\"><td>"+entryString+"</td></tr>\n");
				else
					fout.write("<tr class=\"recv\"><td>"+entryString+"</td></tr>\n");
			}
			fout.write("</tbody></table></div>");
		}
		fout.write("</body></html>\n");
		fout.flush();
		fout.close();
		return filename;
	}

	/** Gets localized date and now properly formatted */
	private String now() {
		return formatter.format(new Date());
	}
}
