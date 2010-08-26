LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ALL_PREBUILT += $(TARGET_OUT)/usr/share/zoneinfo/zoneinfo.dat
$(TARGET_OUT)/usr/share/zoneinfo/zoneinfo.dat : $(LOCAL_PATH)/zoneinfo.dat | $(ACP)
	$(transform-prebuilt-to-target)

ALL_PREBUILT += $(TARGET_OUT)/usr/share/zoneinfo/zoneinfo.idx
$(TARGET_OUT)/usr/share/zoneinfo/zoneinfo.idx : $(LOCAL_PATH)/zoneinfo.idx | $(ACP)
	$(transform-prebuilt-to-target)

ALL_PREBUILT += $(TARGET_OUT)/usr/share/zoneinfo/zoneinfo.version
$(TARGET_OUT)/usr/share/zoneinfo/zoneinfo.version : $(LOCAL_PATH)/zoneinfo.version | $(ACP)
	$(transform-prebuilt-to-target)
