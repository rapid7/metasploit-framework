package com.xenoamess.metasploit.java_external_module.core.contexts;

import com.xenoamess.metasploit.java_external_module.core.entities.MsfRequest;
import com.xenoamess.metasploit.java_external_module.core.handle.MsfRequestHandleManager;
import com.xenoamess.metasploit.java_external_module.core.handle.MsfRequestHandler;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.xenoamess.metasploit.java_external_module.core.utils.JsonUtil.getObjectMapper;

public class MsfContext {

    private static final transient Logger LOGGER =
            LoggerFactory.getLogger(MsfContext.class);

    private final MsfRequestHandleManager msfRequestHandleManager = new MsfRequestHandleManager();

    public MsfContext(MsfRequestHandler... msfRequestHandlers) {
        for (MsfRequestHandler msfRequestHandler : msfRequestHandlers) {
            this.msfRequestHandleManager.addHandler(msfRequestHandler);
        }
    }

    public void run(String[] args) {
        LOGGER.info("--------------------args output started:");
        LOGGER.info(Arrays.toString(args));
        LOGGER.info("--------------------args output ends.");

        LOGGER.info("--------------------stdin output started:");

        try {
            MsfRequest msfRequest = getObjectMapper().readValue(System.in, MsfRequest.class);
            LOGGER.info("msfRequest be: {}", getObjectMapper().writeValueAsString(msfRequest));
            Object result = this.getMsfRequestHandleManager().handle(msfRequest);
            LOGGER.info("result be: {}", getObjectMapper().writeValueAsString(result));
            System.out.println(
                    getObjectMapper().writeValueAsString(result)
            );
        } catch (Exception e) {
            LOGGER.error("exception", e);
        }

        LOGGER.info("--------------------stdin output ends.");
    }

    //-----getters and setters

    public MsfRequestHandleManager getMsfRequestHandleManager() {
        return msfRequestHandleManager;
    }

}
