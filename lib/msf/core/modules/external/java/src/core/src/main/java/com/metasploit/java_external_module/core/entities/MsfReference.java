package com.metasploit.java_external_module.core.entities;

import org.jetbrains.annotations.NotNull;

public class MsfReference {
    private String type;
    private String ref;

    public MsfReference() {
    }

    public MsfReference(String type, String ref) {
        this.type = type;
        this.ref = ref;
    }

    //-----getters and setters

    @NotNull
    @Override
    public String toString() {
        return "MsfReference{" +
                "type='" + type + '\'' +
                ", ref='" + ref + '\'' +
                '}';
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getRef() {
        return ref;
    }

    public void setRef(String ref) {
        this.ref = ref;
    }
}
