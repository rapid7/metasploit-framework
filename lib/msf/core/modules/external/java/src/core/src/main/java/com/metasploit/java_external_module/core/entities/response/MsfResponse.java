package com.metasploit.java_external_module.core.entities.response;

import com.metasploit.java_external_module.core.entities.MsfRequest;
import org.jetbrains.annotations.NotNull;

public class MsfResponse<T> {
    /**
     * json rpc version.
     * should be "2.0" when writing this class at 2021/02/14
     * @see MsfRequest#getJsonrpc()
     */
    private String jsonrpc;

    /**
     * id of this connection.
     * @see MsfRequest#getId()
     */
    private String id;

    /**
     * result
     */
    private T result;

    public MsfResponse() {
    }

    public MsfResponse(String jsonrpc, String id, T result) {
        this.jsonrpc = jsonrpc;
        this.id = id;
        this.result = result;
    }

    //-----getters and setters

    @NotNull
    @Override
    public String toString() {
        return "MsfResponse{" +
                "jsonrpc='" + jsonrpc + '\'' +
                ", id='" + id + '\'' +
                ", result=" + result +
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

    public T getResult() {
        return result;
    }

    public void setResult(T result) {
        this.result = result;
    }
}
