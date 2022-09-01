LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	poc.c

LOCAL_MODULE    := poc

include $(BUILD_EXECUTABLE)

