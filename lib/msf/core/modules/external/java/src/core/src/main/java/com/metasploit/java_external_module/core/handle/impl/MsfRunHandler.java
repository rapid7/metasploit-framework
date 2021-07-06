package com.metasploit.java_external_module.core.handle.impl;

import com.metasploit.java_external_module.core.entities.MsfRequest;
import com.metasploit.java_external_module.core.entities.response.MsfRunResponseResult;
import com.metasploit.java_external_module.core.entities.response.MsfResponse;
import com.metasploit.java_external_module.core.enums.MsfMethodTypeEnum;
import com.metasploit.java_external_module.core.function.ThrowableFunction;
import com.metasploit.java_external_module.core.handle.MsfCannotHandleException;
import com.metasploit.java_external_module.core.handle.MsfRequestHandler;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import static com.metasploit.java_external_module.core.enums.MsfMethodTypeEnum.RUN;

public class MsfRunHandler implements MsfRequestHandler<MsfRequest, MsfResponse<MsfRunResponseResult>> {

    private final ThrowableFunction<MsfRequest, Object> runFunction;

    public MsfRunHandler() {
        this(null);
    }

    public MsfRunHandler(@Nullable ThrowableFunction<MsfRequest, Object> runFunction) {
        this.runFunction = runFunction;
    }

    @Override
    public @NotNull MsfMethodTypeEnum[] handleMethodTypes() {
        return new MsfMethodTypeEnum[]{RUN};
    }

    @Nullable
    @Override
    public MsfResponse<MsfRunResponseResult> handle(@NotNull MsfRequest msfRequest) throws MsfCannotHandleException {
        Object returnValue = null;
        if (runFunction != null) {
            try {
                returnValue = runFunction.apply(msfRequest);
            } catch (Throwable t) {
                throw MsfCannotHandleException.errorWhenHandle(this, msfRequest, t);
            }
        }
        return new MsfResponse<>(msfRequest.getJsonrpc(), msfRequest.getId(),
                new MsfRunResponseResult("Module completed", returnValue));
    }

}
