package com.metasploit.java_external_module.core.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.metasploit.java_external_module.core.entities.MsfRequest;
import com.metasploit.java_external_module.core.enums.MsfLogLevelEnum;
import com.metasploit.java_external_module.core.entities.response.MsfResponse;
import java.util.HashMap;
import java.util.LinkedHashMap;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MsfCommandLineUtil {

    private static final transient Logger LOGGER =
            LoggerFactory.getLogger(MsfCommandLineUtil.class);

    public static void logRaw(@NotNull MsfLogLevelEnum level, @Nullable String messageString) throws JsonProcessingException {
        HashMap<String, Object> params = new LinkedHashMap<>(2);
        params.put("level", level.getKey());
        params.put("message", messageString);
        MsfRequest msfRequest = new MsfRequest(
                "2.0",
                null,
                "message",
                params
        );
        String res = JsonUtil.getObjectMapper().writeValueAsString(
                msfRequest
        );
        LOGGER.info("logRaw : {}", res);
        System.out.println(res);
    }

    public static void logJson(@NotNull MsfLogLevelEnum level, @Nullable Object messageObject) throws JsonProcessingException {
        logRaw(level, JsonUtil.toJsonString(messageObject));
    }

    public static void reportRaw(@Nullable String kind, @Nullable String dataString) throws JsonProcessingException {
        HashMap<String, Object> params = new LinkedHashMap<>(2);
        params.put("type", "report");
        params.put("data", dataString);
        MsfRequest msfRequest = new MsfRequest(
                "2.0",
                null,
                kind,
                params
        );
        String res = JsonUtil.getObjectMapper().writeValueAsString(
                msfRequest
        );
        LOGGER.info("reportRaw : {}", res);
        System.out.println(res);
    }

    public static void reportJson(@Nullable String kind, @Nullable Object dataObject) throws JsonProcessingException {
        reportRaw(kind, JsonUtil.toJsonString(dataObject));
    }

    public static void ret(@NotNull String id, @Nullable Object retObject) throws JsonProcessingException {
        MsfResponse msfResponse = new MsfResponse(
                "2.0",
                "report",
                retObject
        );
        String res = JsonUtil.getObjectMapper().writeValueAsString(
                msfResponse
        );
        LOGGER.info("reportRaw : {}", res);
        System.out.println(res);
    }
}
