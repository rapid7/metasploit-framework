package com.xenoamess.metasploit.java_external_module.core.enums;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public enum MsfLogLevelEnum {
    /**
     * info
     */
    INFO("info", "*"),

    /**
     * good
     */
    GOOD("good", "+"),

    /**
     * warning
     */
    WARNING("warning", "!"),

    /**
     * error
     */
    ERROR("error", "!");

    MsfLogLevelEnum(@NotNull String key, @NotNull String signal) {
        this.key = key;
        this.signal = signal;
    }

    @NotNull
    private final String key;

    @NotNull
    private final String signal;


    @Nullable
    public static MsfLogLevelEnum getByKey(@Nullable String key) {
        for (MsfLogLevelEnum msfLogLevelEnum : MsfLogLevelEnum.values()) {
            if (msfLogLevelEnum.key.equals(key)) {
                return msfLogLevelEnum;
            }
        }
        return INFO;
    }

    //-----getters and setters

    @NotNull
    public String getKey() {
        return key;
    }

    @NotNull
    public String getSignal() {
        return signal;
    }
}
