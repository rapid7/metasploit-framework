package com.xenoamess.metasploit.java_external_module.core.entities.response;

import com.xenoamess.metasploit.java_external_module.core.entities.MsfOption;
import com.xenoamess.metasploit.java_external_module.core.entities.MsfReference;
import com.xenoamess.metasploit.java_external_module.core.enums.MsfPluginTypeEnum;
import java.util.LinkedHashMap;
import java.util.List;
import org.jetbrains.annotations.NotNull;

public class MsfMetadata {

    private String name;
    private String description;
    private List<String> authors;
    private String date;
    private String license;
    private List<MsfReference> references;

    /**
     * type of the plugin.
     * @see MsfPluginTypeEnum
     */
    private String type;

    private LinkedHashMap<String, MsfOption> options;


    public MsfMetadata() {
    }

    public MsfMetadata(
            String name,
            String description,
            List<String> authors,
            String date,
            String license,
            List<MsfReference> references,
            String type,
            LinkedHashMap<String, MsfOption> options
    ) {
        this.name = name;
        this.description = description;
        this.authors = authors;
        this.date = date;
        this.license = license;
        this.references = references;
        this.type = type;
        this.options = options;
    }

    @NotNull
    @Override
    public String toString() {
        return "MsfMetadata{" +
                "name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", authors='" + authors + '\'' +
                ", date='" + date + '\'' +
                ", license='" + license + '\'' +
                ", references=" + references +
                ", type='" + type + '\'' +
                ", options=" + options +
                '}';
    }

    //-----getters and setters

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getAuthors() {
        return authors;
    }

    public void setAuthors(List<String> authors) {
        this.authors = authors;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getLicense() {
        return license;
    }

    public void setLicense(String license) {
        this.license = license;
    }

    public List<MsfReference> getReferences() {
        return references;
    }

    public void setReferences(List<MsfReference> references) {
        this.references = references;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public LinkedHashMap<String, MsfOption> getOptions() {
        return options;
    }

    public void setOptions(LinkedHashMap<String, MsfOption> options) {
        this.options = options;
    }
}
