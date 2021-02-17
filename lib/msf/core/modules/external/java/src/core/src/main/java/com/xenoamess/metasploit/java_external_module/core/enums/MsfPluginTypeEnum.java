package com.xenoamess.metasploit.java_external_module.core.enums;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public enum MsfPluginTypeEnum {
    /**
     *
     */
    REMOTE_EXPLOIT("remote_exploit"),

    /**
     * The remote_exploit_cmd_stager module type is used when writing an exploit for command execution or code
     * injection vulnerabilities and provides the command to inject into the vulnerable code based on the flavor
     * specified for the command stager.
     */
    REMOTE_EXPLOIT_CMD_STAGER("remote_exploit_cmd_stager"),

    /**
     * The capture_server module type is used when a module is designed to simulate a service to capture credentials
     * for connecting clients.
     */
    CAPTURE_SERVER("capture_server"),

    /**
     * The dos module type is used when the module will send packets to a remote service that will crash the service
     * or put it in an unusable state.
     */
    DOS("dos"),

    /**
     * The single_scanner module type is used when creating a module to scan hosts without batching.
     */
    SINGLE_SCANNER("single_scanner"),

    /**
     *
     */
    SINGLE_HOST_LOGIN_SCANNER("single_host_login_scanner"),

    /**
     * The multi_scanner module type is used for modules that are going to scan hosts in batches. The batch_size
     * option is registered in the mutli_scanner ERB template with a default of 200.
     */
    MULTI_SCANNER("multi_scanner");

    MsfPluginTypeEnum(@NotNull String key) {
        this.key = key;
    }

    @NotNull
    private final String key;

    @Nullable
    public static MsfPluginTypeEnum getByKey(@Nullable String key) {
        for (MsfPluginTypeEnum msfPluginTypeEnum : MsfPluginTypeEnum.values()) {
            if (msfPluginTypeEnum.key.equals(key)) {
                return msfPluginTypeEnum;
            }
        }
        return null;
    }

    //-----getters and setters

    @NotNull
    public String getKey() {
        return key;
    }
}
