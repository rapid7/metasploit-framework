package msfgui;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * This class keeps a record of activities taken, sessions run, and
 * credentials collected
 * @author scriptjunkie
 */
public class MsfguiLog {
	final protected Map sessions; // maps session ids to sessions
	final protected ArrayList activityLog; // list of strings denoting major activities
	final protected DateFormat formatter;
	final protected Set hashes;
	final protected Pattern hashPattern;
	public static MsfguiLog defaultLog;

	/** Sets up default log */
	public static void initDefaultLog(){
		defaultLog = new MsfguiLog();
	}

	/** Creates a new log to be written to a file */
	public MsfguiLog() {
		sessions = new HashMap();
		activityLog = new ArrayList();
		hashes = new HashSet();
		formatter = DateFormat.getDateTimeInstance();
		activityLog.add(now()+" msfgui started.");
		hashPattern = Pattern.compile("\\w+:[0-9]+:\\w+:\\w+:::");
	}
	/** Records hashes in string */
	public void logHashes(String hashString){
		for(String line : hashString.split("\n"))
			if(hashPattern.matcher(line).matches()) // we are done.
				hashes.add(line);
	}
	/** Returns a list of hashes. */
	public Set getHashes(){
		return hashes;
	}
	/** Ensure that a session is recorded in the sessions map */
	public void logSession(Map session){
		if(sessions.get(session.get("id")) != null)
			return;
		sessions.put(session.get("id"), session);
		activityLog.add(now() + "  Session "+session.get("id")+" to "+session.get("tunnel_peer")+" opened.");
	}
	/** See if any sessions have been closed. */
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
	/** Logs module runs and console commands */
	public void logMethodCall(String methodName, Object[] params){
		if(methodName.startsWith("session.")){
			try{
				if (methodName.endsWith("_write"))
					logConsole(params[0].toString(), new String(Base64.decode(params[1].toString())), true);
				else if (methodName.endsWith("_script"))
					logConsole(params[0].toString(), "run "+params[1].toString(), true);
			}catch (MsfException mex){
			}
		}else if (methodName.equals("module.execute")){
			activityLog.add(now() + "  "+params[0]+" "+params[1]+" executed with options "+params[2]);
		}
	}
	/** Logs received console data */
	public void logMethodReturn(String methodName, Object[] params, Object result){
		if(!methodName.startsWith("session.") || !methodName.endsWith("_read"))
			return;
		try{
			String resString =  new String(Base64.decode(((Map)result).get("data").toString()));
			logConsole(params[0].toString(), resString, false);
			logHashes(resString);
		}catch (MsfException mex){
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
				 "tr.sent td {background-color: #EEFFEE; color: black;}\n" +
				 "tr.recv td {background-color: #EEEEFF; color: black;}\n" +
				 "div.session {float: left; padding-right: 10px;}\n" +
				 "#page{margin:0 auto; padding:30px 200px;}\n" +
				"</style></head>\n<body>\n<div id=\"page\"><h1 class=\"header\">msfgui</h1>");
		
		//Host summary
		//Add headers
		fout.write("<h1>Hosts</h1>");
		Set sessionsEntrySet = sessions.entrySet();
		if(sessions.isEmpty()){
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
			fout.write("<td>type</td><td>via_exploit</td><td>via_payload</td><td>tunnel_peer</td><td>tunnel_local</td><td>desc</td>");
		
			HashMap hosts = new HashMap();
			//Map hosts to sessions by IP
			for(Object e : sessionsEntrySet){
				Map session = (Map)((Entry) e).getValue();
				String host = session.get("tunnel_peer").toString().split(":")[0];
				Set hostSet = (Set)hosts.get(host);
				if(hostSet == null){
					hostSet = new HashSet();
					hosts.put(host, hostSet);
				}
				hostSet.add(session);
			}
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
			fout.write("<tr><td>"+o.toString()+"</td></tr>\n");
		fout.write("</tbody></table>\n\n");
		
		//Complete console logs
		fout.write("<h1>Session logs</h1>\n");
		for(Object e : sessionsEntrySet){
			Entry ent = (Entry) e;
			Object log = ((Map)(ent.getValue())).get("console");
			if(log == null)
				continue;
			Map session = (Map)ent.getValue();
			fout.write("<div class=\"session\"><h2>Session "+ent.getKey()+"</h2>To " +
					session.get("tunnel_peer")+"<table><tbody>\n");
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
