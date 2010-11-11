#ifndef _METERPRETER_SOURCE_EXTENSION_WEBCAM_SERVER_VIDEO_H
#define _METERPRETER_SOURCE_EXTENSION_WEBCAM_SERVER_VIDEO_H

#define TLV_TYPE_EXTENSION_WEBCAM	0

#define TLV_TYPE_WEBCAM_IMAGE				\
		MAKE_CUSTOM_TLV(					\
				TLV_META_TYPE_RAW,			\
				TLV_TYPE_EXTENSION_WEBCAM,	\
				TLV_EXTENSIONS + 1)

#define TLV_TYPE_WEBCAM_INTERFACE_ID		\
		MAKE_CUSTOM_TLV(					\
				TLV_META_TYPE_UINT,			\
				TLV_TYPE_EXTENSION_WEBCAM,	\
				TLV_EXTENSIONS + 2)

#define TLV_TYPE_WEBCAM_QUALITY				\
		MAKE_CUSTOM_TLV(					\
				TLV_META_TYPE_UINT,			\
				TLV_TYPE_EXTENSION_WEBCAM,	\
				TLV_EXTENSIONS + 3)

#define TLV_TYPE_WEBCAM_NAME				\
		MAKE_CUSTOM_TLV(					\
				TLV_META_TYPE_STRING,		\
				TLV_TYPE_EXTENSION_WEBCAM,	\
				TLV_EXTENSIONS + 4)

DWORD request_webcam_list(Remote *remote, Packet *packet);
DWORD request_webcam_start(Remote *remote, Packet *packet);
DWORD request_webcam_get_frame(Remote *remote, Packet *packet);
DWORD request_webcam_stop(Remote *remote, Packet *packet);
#endif
