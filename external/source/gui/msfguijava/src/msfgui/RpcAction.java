package msfgui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Map;

/**
 * Provides an ActionListener for running a meterpreter script on each selected session. Each time
 * the action is executed, the command is retrieved from the toString() method of commandGenerator
 * and executed on each session.
 * @author scriptjunkie
 */
public class RpcAction implements ActionListener {
	protected Object commandGenerator = null;
	protected String command = null;
	protected MainFrame parent = null;
	public RpcAction(){
	}
	public RpcAction( MainFrame parent){
		this.parent = parent;
	}
	public RpcAction(Object commandGenerator, MainFrame parent){
		this.commandGenerator = commandGenerator;
		this.parent = parent;
	}
	public void actionPerformed(ActionEvent e){
		try{
			prepare();
			if(parent == null)
				action();
			else
				for(Map session : parent.selectedSessions)
					action(session);
		}catch(Exception ex){
			if(!ex.getMessage().equals("cancelled")){
				MsfguiApp.showMessage(null, "Error in RPC call: "+ex);
				ex.printStackTrace();
			}
		}
	}
	/** prepare() is provided to prepare state of action handler
	 * such as preparing a command that will be run on all selected sessions. */
	public void prepare() throws Exception{
		if(commandGenerator != null)
			command = commandGenerator.toString();
	}
	/** action() with no args provided as an exception-handling action listener. */
	public void action() throws Exception{
		if (parent == null)
			throw new MsfException("Error: no parent. If using default constructor, must override action().");
	}
	/** Default action executes session.meterpreter_script and shows console window. */
	public void action(Map session) throws Exception{
		if(commandGenerator != null)
			parent.rpcConn.execute("session.meterpreter_script", session.get("id"), command);
		parent.showInteractWindow();
	}
}
