package com.xenoamess.metasploit.java_external_module.core.entities;

import com.xenoamess.metasploit.java_external_module.core.enums.MsfMethodTypeEnum;
import java.util.HashMap;
import org.jetbrains.annotations.NotNull;

/**
 * MsfRequest class.
 */
public class MsfRequest {
    /**
     * json rpc version.
     * should be "2.0" when writing this class at 2021/02/14
     */
    private String jsonrpc;

    /**
     * id of this connection.
     * we should copy this into response.
     */
    private String id;

    /**
     * the method they want to invoke.
     * @see MsfMethodTypeEnum
     */
    private String method;

    /**
     * params of this invoke.
     */
    private HashMap<String, Object> params;

    public MsfRequest() {
    }

    public MsfRequest(String jsonrpc, String id, String method, HashMap<String, Object> params) {
        this.jsonrpc = jsonrpc;
        this.id = id;
        this.method = method;
        this.params = params;
    }

    //-----getters and setters

    @NotNull
    @Override
    public String toString() {
        return "MsfRequest{" +
                "jsonrpc='" + jsonrpc + '\'' +
                ", id='" + id + '\'' +
                ", method='" + method + '\'' +
                ", params='" + params + '\'' +
                '}';
    }

    public String getJsonrpc() {
        return jsonrpc;
    }

    public void setJsonrpc(String jsonrpc) {
        this.jsonrpc = jsonrpc;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public HashMap<String, Object> getParams() {
        return params;
    }

    public void setParams(HashMap<String, Object> params) {
        this.params = params;
    }

}
