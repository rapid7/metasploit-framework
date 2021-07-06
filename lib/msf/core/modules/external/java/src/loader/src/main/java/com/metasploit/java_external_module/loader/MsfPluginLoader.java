package com.metasploit.java_external_module.loader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.metasploit.java_external_module.core.enums.MsfLogLevelEnum;
import com.metasploit.java_external_module.core.utils.MsfCommandLineUtil;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MsfPluginLoader {

    private static final transient Logger LOGGER =
            LoggerFactory.getLogger(MsfPluginLoader.class);

    /**
     * @param args args[0] should be module filePath
     */
    public static void main(String[] args) {
        LOGGER.info("MsfPluginLoader invoked, args be : {}", args);
        if (ArrayUtils.isEmpty(args)) {
            try {
                MsfCommandLineUtil.logJson(
                        MsfLogLevelEnum.ERROR,
                        "args num not correct! should at least have one arg, means the module file to load."
                );
            } catch (JsonProcessingException ignored) {
            }
            LOGGER.error("args num not correct! should at least have one arg, means the module file to load.");
            return;
        }

        String moduleFilePath = args[0];
        File moduleFile = new File(moduleFilePath);
        String moduleFileName = moduleFile.getName();
        String moduleClassName = moduleFileName.substring(0, moduleFileName.length() - ".java".length());
        String moduleFileContent = null;
        try {
            moduleFileContent = FileUtils.readFileToString(moduleFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            try {
                MsfCommandLineUtil.logJson(
                        MsfLogLevelEnum.ERROR,
                        "module file load failed : " + moduleFileName
                );
            } catch (JsonProcessingException ignored) {
            }
            LOGGER.error("module file load failed : " + moduleFileName, e);
            return;
        }

        Jdk8Compiler jdk8Compiler = new Jdk8Compiler();

        Class moduleClass = null;
        try {
            moduleClass = jdk8Compiler.doCompile(
                    moduleClassName,
                    moduleFileContent
            );
        } catch (Throwable throwable) {
            try {
                MsfCommandLineUtil.logJson(
                        MsfLogLevelEnum.ERROR,
                        "module compile failed : " + moduleFileName
                );
            } catch (JsonProcessingException ignored) {
            }
            LOGGER.error("module compile failed : " + moduleFileName, throwable);
            return;
        }

        Method mainMethod = null;
        try {
            mainMethod = moduleClass.getDeclaredMethod("main", String[].class);
        } catch (NoSuchMethodException e) {
            try {
                MsfCommandLineUtil.logJson(
                        MsfLogLevelEnum.ERROR,
                        "module find main method failed : " + moduleFileName
                );
            } catch (JsonProcessingException ignored) {
            }
            LOGGER.error("module find main method failed : " + moduleFileName, e);
            return;
        }

        try {
            mainMethod.invoke(null, new Object[]{args});
        } catch (IllegalAccessException | InvocationTargetException e) {
            try {
                MsfCommandLineUtil.logJson(
                        MsfLogLevelEnum.ERROR,
                        "module invoke failed : " + moduleFileName
                );
            } catch (JsonProcessingException ignored) {
            }
            LOGGER.error("module invoke failed : " + moduleFileName, e);
            return;
        }

        LOGGER.info("module invoke ended : {}", moduleFileName);
    }
}
