package msfgui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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
	public RpcAction(Object arg, MainFrame parent){
		this.arg = arg;
		this.parent = parent;
	}
	public void actionPerformed(ActionEvent e){
		try{
			action();
		}catch(Exception ex){
			if(!ex.getMessage().equals("cancelled"))
				JOptionPane.showMessageDialog(null, "Error in RPC call: "+ex);
		}
	}
	/* Default action executes session.meterpreter_script and shows console window. */
	public void action() throws Exception{
		if(arg != null)
			parent.rpcConn.execute("session.meterpreter_script", new Object[]{parent.session.get("id"), getCmd()});
		else if (parent == null)
			throw new MsfException("Error: no parent. If using default constructor, must override action().");
		parent.showInteractWindow();
	}
}
