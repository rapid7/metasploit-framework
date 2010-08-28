package msfgui;

import java.util.List;
import java.util.Map;
import javax.swing.JLabel;
import org.jdesktop.swingworker.SwingWorker;

/**
 *
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
					rpcConn.execute("session.meterpreter_write", session.get("id"),Base64.encode(("\n"
							+sess.getCommand(session, this)+"\n").getBytes()));
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
