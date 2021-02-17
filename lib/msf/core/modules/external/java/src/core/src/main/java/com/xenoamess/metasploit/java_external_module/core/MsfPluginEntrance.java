package com.xenoamess.metasploit.java_external_module.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.xenoamess.metasploit.java_external_module.core.contexts.MsfContext;
import com.xenoamess.metasploit.java_external_module.core.entities.MsfRequest;
import com.xenoamess.metasploit.java_external_module.core.enums.MsfLogLevelEnum;
import com.xenoamess.metasploit.java_external_module.core.handle.impl.MsfDescribeHandler;
import com.xenoamess.metasploit.java_external_module.core.handle.impl.MsfRunHandler;
import com.xenoamess.metasploit.java_external_module.core.utils.MsfCommandLineUtil;

public class MsfPluginEntrance {

    public Object handleRun(MsfRequest msfRequest) throws JsonProcessingException {
        MsfCommandLineUtil.logJson(
                MsfLogLevelEnum.ERROR,
                "YOU FORGOT TO SET PROPERTY mainClass IN pom.xml's properties!!!"
        );
        return msfRequest.getParams();
    }

    public static void main(String[] args) {
        MsfPluginEntrance msfPluginEntrance = new MsfPluginEntrance();
        MsfContext msfContext = new MsfContext(
                new MsfDescribeHandler("msf_plugin_help_resources/help_metadata.json"),
                new MsfRunHandler(msfPluginEntrance::handleRun)
        );
        msfContext.run(args);
    }
}
