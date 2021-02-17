package com.xenoamess.metasploit.java_external_module.core.enums;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public enum MsfMethodTypeEnum {
    /**
     * to describe this plugin.
     */
    DESCRIBE("describe"),

    /**
     * what the hell is this?
     * anyway, both Python and Go external module did not really implement it,
     * so neither will I.
     */
    SOFT_CHECK("soft_check"),

    /**
     * to run this plugin.
     */
    RUN("run"),
    ;

    MsfMethodTypeEnum(@NotNull String key) {
        this.key = key;
    }

    @NotNull
    private final String key;

    @Nullable
    public static MsfMethodTypeEnum getByKey(@Nullable String key) {
        for (MsfMethodTypeEnum msfMethodTypeEnum : MsfMethodTypeEnum.values()) {
            if (msfMethodTypeEnum.key.equals(key)) {
                return msfMethodTypeEnum;
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
