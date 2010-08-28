package msfgui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Map;
import javax.swing.JOptionPane;

/**
 *
 * @author scriptjunkie
 */
public class RpcAction implements ActionListener {
	protected Object arg = null;
	protected MainFrame parent = null;
	public String getCmd(){
		return arg.toString();
	}
	public RpcAction(){
	}
	public RpcAction( MainFrame parent){
		this.parent = parent;
	}
	public RpcAction(Object arg, MainFrame parent){
		this.arg = arg;
		this.parent = parent;
	}
	public void actionPerformed(ActionEvent e){
		try{
			if(parent == null)
				action();
			else
				for(Map session : parent.selectedSessions)
					action(session);
		}catch(Exception ex){
			if(!ex.getMessage().equals("cancelled"))
				JOptionPane.showMessageDialog(null, "Error in RPC call: "+ex);
		}
	}
	/** action() with no args provided as an exception-handling action listener. */
	public void action() throws Exception{
		if (parent == null)
			throw new MsfException("Error: no parent. If using default constructor, must override action().");
	}
	/** Default action executes session.meterpreter_script and shows console window. */
	public void action(Map session) throws Exception{
		if(arg != null)
			parent.rpcConn.execute("session.meterpreter_script", session.get("id"), getCmd());
		parent.showInteractWindow();
	}
}
