package com.xenoamess.metasploit.java_external_module.core.entities.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.NotNull;

public class MsfRunResponseResult {
    private String message;

    @JsonProperty("return")
    private Object returnField;

    public MsfRunResponseResult() {
    }

    public MsfRunResponseResult(String message, Object returnField) {
        this.message = message;
        this.returnField = returnField;
    }

    //-----getters and setters

    @NotNull
    @Override
    public String toString() {
        return "MsfRunResponseResult{" +
                "message='" + message + '\'' +
                ", returnField='" + returnField + '\'' +
                '}';
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Object getReturnField() {
        return returnField;
    }

    public void setReturnField(Object returnField) {
        this.returnField = returnField;
    }
}
