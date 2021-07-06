package com.metasploit.java_external_module.core.handle;

import com.metasploit.java_external_module.core.entities.MsfRequest;
import com.metasploit.java_external_module.core.enums.MsfMethodTypeEnum;
import org.apache.commons.lang3.ArrayUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public interface MsfRequestHandler<REQUEST extends MsfRequest, RESPONSE> {

    /**
     * return the method types that this handler can handle.
     *
     * @return method types
     */
    @NotNull
    MsfMethodTypeEnum[] handleMethodTypes();

    /**
     * detect if this handler can handle this method type
     *
     * @param methodType methodType
     * @return if this handler can handle this method type
     */
    default boolean canHandle(@Nullable MsfMethodTypeEnum methodType) {
        return ArrayUtils.contains(this.handleMethodTypes(), methodType);
    }

    /**
     * handle a request
     *
     * @param msfRequest request
     * @return anything you want
     * @throws MsfCannotHandleException when fail to find a correct handler
     */
    @Nullable
    RESPONSE handle(@NotNull REQUEST msfRequest) throws MsfCannotHandleException;

}
