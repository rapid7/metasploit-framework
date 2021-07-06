package com.metasploit.java_external_module.core.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.NotNull;

public class MsfOption {
    private String type;
    private String description;
    private Boolean required;
    @JsonProperty("default")
    private String defaultField;

    public MsfOption() {
    }

    public MsfOption(String type, String description, Boolean required, String defaultField) {
        this.type = type;
        this.description = description;
        this.required = required;
        this.defaultField = defaultField;
    }

    //-----getters and setters

    @NotNull
    @Override
    public String toString() {
        return "MsfOption{" +
                "type='" + type + '\'' +
                ", description='" + description + '\'' +
                ", required=" + required +
                ", defaultField='" + defaultField + '\'' +
                '}';
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Boolean getRequired() {
        return required;
    }

    public void setRequired(Boolean required) {
        this.required = required;
    }

    public String getDefaultField() {
        return defaultField;
    }

    public void setDefaultField(String defaultField) {
        this.defaultField = defaultField;
    }

}
