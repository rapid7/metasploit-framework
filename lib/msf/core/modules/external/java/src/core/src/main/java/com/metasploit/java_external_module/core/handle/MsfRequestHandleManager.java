package com.metasploit.java_external_module.core.handle;

import com.metasploit.java_external_module.core.entities.MsfRequest;
import com.metasploit.java_external_module.core.enums.MsfMethodTypeEnum;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentLinkedDeque;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * manager class for MsfRequestHandler
 */
public class MsfRequestHandleManager {

    private final ConcurrentLinkedDeque<MsfRequestHandler> handlers = new ConcurrentLinkedDeque<>();

    public void addHandler(@NotNull MsfRequestHandler msfRequestHandler) {
        handlers.addFirst(msfRequestHandler);
    }

    public void removeHandler(@NotNull MsfRequestHandler msfRequestHandler) {
        handlers.remove(msfRequestHandler);
    }

    public void removeAllHandlers() {
        handlers.clear();
    }

    public ArrayList<MsfRequestHandler> listHandlers() {
        return new ArrayList<>(this.handlers);
    }

    @Nullable
    public MsfRequestHandler getHandler(@Nullable MsfMethodTypeEnum methodType) {
        for (MsfRequestHandler requestHandler : handlers) {
            if (requestHandler.canHandle(methodType)) {
                return requestHandler;
            }
        }
        return null;
    }

    /**
     * handle a msfRequest
     *
     * @param msfRequest request
     * @return result from the handler
     * @throws MsfCannotHandleException when fail to find a correct handler
     */
    @Nullable
    public Object handle(@NotNull MsfRequest msfRequest) throws MsfCannotHandleException {
        MsfRequestHandler msfRequestHandler = this.getHandler(MsfMethodTypeEnum.getByKey(msfRequest.getMethod()));
        if (msfRequestHandler == null) {
            throw MsfCannotHandleException.cannotFindHandlerForRequest(msfRequest);
        }
        return msfRequestHandler.handle(msfRequest);
    }

    /**
     * handle a msfRequest, and assert result type.
     *
     * @param msfRequest request
     * @param tClass assert type of the result
     * @return result from the handler
     * @throws MsfCannotHandleException when fail to find a correct handler, or result
     */
    @Nullable
    public <T> T handle(@NotNull MsfRequest msfRequest, @NotNull Class<T> tClass) throws MsfCannotHandleException {
        MsfRequestHandler msfRequestHandler = this.getHandler(MsfMethodTypeEnum.getByKey(msfRequest.getMethod()));
        if (msfRequestHandler == null) {
            throw MsfCannotHandleException.cannotFindHandlerForRequest(msfRequest);
        }
        Object result = msfRequestHandler.handle(msfRequest);
        if (result != null && !tClass.isInstance(result)) {
            throw MsfCannotHandleException.resultTypeNotCorrect(
                    msfRequestHandler,
                    msfRequest,
                    tClass,
                    result
            );
        }
        //noinspection unchecked
        return (T) result;
    }

}
