#ifndef _METERPRETER_SOURCE_EXTENSION_WEBCAM_SERVER_VIDEO_H
#define _METERPRETER_SOURCE_EXTENSION_WEBCAM_SERVER_VIDEO_H
DWORD request_webcam_list(Remote *remote, Packet *packet);
DWORD request_webcam_start(Remote *remote, Packet *packet);
DWORD request_webcam_get_frame(Remote *remote, Packet *packet);
DWORD request_webcam_stop(Remote *remote, Packet *packet);
#endif
