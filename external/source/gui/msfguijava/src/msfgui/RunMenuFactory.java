package msfgui;

import java.awt.event.ActionListener;

/**
 *
 * @author scriptjunkie
 */
public interface RunMenuFactory {
	
	public ActionListener getActor(String modName, String type, RpcConnection rpcConn);
}
