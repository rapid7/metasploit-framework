package com.xenoamess.metasploit.java_external_module.core.handle;

import com.xenoamess.metasploit.java_external_module.core.entities.MsfRequest;
import org.jetbrains.annotations.NotNull;

public class MsfCannotHandleException extends RuntimeException {

    public MsfCannotHandleException() {
        super();
    }

    public MsfCannotHandleException(String message) {
        super(message);
    }

    public MsfCannotHandleException(String message, Throwable cause) {
        super(message, cause);
    }

    public MsfCannotHandleException(Throwable cause) {
        super(cause);
    }

    protected MsfCannotHandleException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace
    ) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    @NotNull
    public static MsfCannotHandleException handlerCannotHandleRequest(
            @NotNull MsfRequestHandler msfRequestHandler,
            @NotNull MsfRequest msfRequest
    ) {
        return new MsfCannotHandleException(
                "A handler cannot handle a request! handler class name : " +
                        msfRequestHandler.getClass().getCanonicalName() +
                        " , msfRequest : " +
                        msfRequest
        );
    }

    @NotNull
    public static MsfCannotHandleException cannotFindHandlerForRequest(@NotNull MsfRequest msfRequest) {
        return new MsfCannotHandleException("can not find handler for a request! msfRequest : " + msfRequest);
    }

    @NotNull
    public static MsfCannotHandleException resultTypeNotCorrect(
            @NotNull MsfRequestHandler msfRequestHandler,
            @NotNull MsfRequest msfRequest,
            @NotNull Class tClass,
            @NotNull Object result
    ) {
        return new MsfCannotHandleException(
                "A handler handles a request but the response have different type than need! handler class name : " +
                        msfRequestHandler.getClass().getCanonicalName() +
                        " , msfRequest : " +
                        msfRequest +
                        " , needed class : " +
                        tClass +
                        " , result : " +
                        result +
                        " , result class : " +
                        result.getClass()
        );
    }

    @NotNull
    public static MsfCannotHandleException errorWhenHandle(
            @NotNull MsfRequestHandler msfRequestHandler,
            @NotNull MsfRequest msfRequest,
            @NotNull Throwable e
    ) {
        return new MsfCannotHandleException(
                "A handler errors when handling a request! handler class name : " +
                        msfRequestHandler.getClass().getCanonicalName() +
                        " , msfRequest : " +
                        msfRequest,
                e
        );
    }

}
