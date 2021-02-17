package com.xenoamess.metasploit.java_external_module.core.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.Nullable;

public class JsonUtil {
    private static ObjectMapper OBJECT_MAPPER;

    public static ObjectMapper getObjectMapper() {
        if (OBJECT_MAPPER == null) {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
            OBJECT_MAPPER = objectMapper;
        }
        return OBJECT_MAPPER;
    }

    public static String toJsonString(@Nullable Object object) throws JsonProcessingException {
        if (object instanceof CharSequence) {
            return object.toString();
        }
        return getObjectMapper().writeValueAsString(object);
    }
}
