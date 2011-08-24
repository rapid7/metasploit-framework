package msfgui;

import java.util.List;
import java.util.Map;
import javax.swing.JLabel;
import org.jdesktop.swingworker.SwingWorker;

/**
 * A class to simplify running a command on a collection of sessions and reporting progress.
 * @author scriptjunkie
 */
public class SessionCommand {
	protected String command;
	protected String outputPrefix;
	protected JLabel label;
	public SessionCommand(){
		command = null;
		outputPrefix = null;
		label = null;
	}
	public SessionCommand(String cmd, String output, JLabel outputLabel){
		command = cmd;
		outputPrefix = output;
		label = outputLabel;
	}
	public String getCommand(Map session, SwingWorker parent){
		return command;
	}
	public void processResult(Map m) {
		label.setText("Running "+outputPrefix + " on " + m.get("tunnel_peer") + ", session " + m.get("id"));
	}
	/** Starts a thread to iterate across active sessions, executing the given command on each,
	 * and updating the output label as progress is made. */
	public static void runOnAllMeterpreters(final SessionsTable sessionsTableModel, String cmd, String output,
			JLabel outputLabel, final RpcConnection rpcConn) {
		final SessionCommand sess =  new SessionCommand(cmd,output,outputLabel);
		new SwingWorker() {
			protected Object doInBackground() throws Exception {
				try{
				List currentSessions = sessionsTableModel.getSessionList();
				for (Object o : currentSessions) {
					Map session = (Map) o;
					if (!session.get("type").equals("meterpreter"))
						continue;
					publish(session);
					rpcConn.execute("session.meterpreter_write", session.get("id"),("\n"
							+sess.getCommand(session, this)+"\n"));
				}
				}catch (RuntimeException rex){
					if(!rex.getMessage().equals("cancelled"))
						throw rex;
				}
				return null;
			}
			protected void process(List l) {
				for(Object o : l)
					sess.processResult((Map)o);
			}
		}.execute();
	}
}
