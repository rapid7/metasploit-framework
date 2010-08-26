/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _MSM_VENC_H_
#define _MSM_VENC_H_

#include <linux/types.h>

#define VENC_MAX_RECON_BUFFERS 2

#define VENC_FLAG_EOS 0x00000001
#define VENC_FLAG_END_OF_FRAME 0x00000010
#define VENC_FLAG_SYNC_FRAME 0x00000020
#define VENC_FLAG_EXTRA_DATA 0x00000040
#define VENC_FLAG_CODEC_CONFIG 0x00000080

enum venc_flush_type {
 VENC_FLUSH_INPUT,
 VENC_FLUSH_OUTPUT,
 VENC_FLUSH_ALL
};

enum venc_state_type {
 VENC_STATE_PAUSE = 0x1,
 VENC_STATE_START = 0x2,
 VENC_STATE_STOP = 0x4
};

enum venc_event_type_enum {
 VENC_EVENT_START_STATUS,
 VENC_EVENT_STOP_STATUS,
 VENC_EVENT_SUSPEND_STATUS,
 VENC_EVENT_RESUME_STATUS,
 VENC_EVENT_FLUSH_STATUS,
 VENC_EVENT_RELEASE_INPUT,
 VENC_EVENT_DELIVER_OUTPUT,
 VENC_EVENT_UNKNOWN_STATUS
};

enum venc_status_code {
 VENC_STATUS_SUCCESS,
 VENC_STATUS_ERROR,
 VENC_STATUS_INVALID_STATE,
 VENC_STATUS_FLUSHING,
 VENC_STATUS_INVALID_PARAM,
 VENC_STATUS_CMD_QUEUE_FULL,
 VENC_STATUS_CRITICAL,
 VENC_STATUS_INSUFFICIENT_RESOURCES,
 VENC_STATUS_TIMEOUT
};

enum venc_msg_code {
 VENC_MSG_INDICATION,
 VENC_MSG_INPUT_BUFFER_DONE,
 VENC_MSG_OUTPUT_BUFFER_DONE,
 VENC_MSG_NEED_OUTPUT_BUFFER,
 VENC_MSG_FLUSH,
 VENC_MSG_START,
 VENC_MSG_STOP,
 VENC_MSG_PAUSE,
 VENC_MSG_RESUME,
 VENC_MSG_STOP_READING_MSG
};

enum venc_error_code {
 VENC_S_SUCCESS,
 VENC_S_EFAIL,
 VENC_S_EFATAL,
 VENC_S_EBADPARAM,
 VENC_S_EINVALSTATE,
 VENC_S_ENOSWRES,
 VENC_S_ENOHWRES,
 VENC_S_EBUFFREQ,
 VENC_S_EINVALCMD,
 VENC_S_ETIMEOUT,
 VENC_S_ENOREATMPT,
 VENC_S_ENOPREREQ,
 VENC_S_ECMDQFULL,
 VENC_S_ENOTSUPP,
 VENC_S_ENOTIMPL,
 VENC_S_ENOTPMEM,
 VENC_S_EFLUSHED,
 VENC_S_EINSUFBUF,
 VENC_S_ESAMESTATE,
 VENC_S_EINVALTRANS
};

enum venc_mem_region_enum {
 VENC_PMEM_EBI1,
 VENC_PMEM_SMI
};

struct venc_buf_type {
 unsigned int region;
 unsigned int phys;
 unsigned int size;
 int offset;
};

struct venc_qp_range {
 unsigned int min_qp;
 unsigned int max_qp;
};

struct venc_frame_rate {
 unsigned int frame_rate_num;
 unsigned int frame_rate_den;
};

struct venc_slice_info {
 unsigned int slice_mode;
 unsigned int units_per_slice;
};

struct venc_extra_data {
 unsigned int slice_extra_data_flag;
 unsigned int slice_client_data1;
 unsigned int slice_client_data2;
 unsigned int slice_client_data3;
 unsigned int none_extra_data_flag;
 unsigned int none_client_data1;
 unsigned int none_client_data2;
 unsigned int none_client_data3;
};

struct venc_common_config {
 unsigned int standard;
 unsigned int input_frame_height;
 unsigned int input_frame_width;
 unsigned int output_frame_height;
 unsigned int output_frame_width;
 unsigned int rotation_angle;
 unsigned int intra_period;
 unsigned int rate_control;
 struct venc_frame_rate frame_rate;
 unsigned int bitrate;
 struct venc_qp_range qp_range;
 unsigned int iframe_qp;
 unsigned int pframe_qp;
 struct venc_slice_info slice_config;
 struct venc_extra_data extra_data;
};

struct venc_nonio_buf_config {
 struct venc_buf_type recon_buf1;
 struct venc_buf_type recon_buf2;
 struct venc_buf_type wb_buf;
 struct venc_buf_type cmd_buf;
 struct venc_buf_type vlc_buf;
};

struct venc_mpeg4_config {
 unsigned int profile;
 unsigned int level;
 unsigned int time_resolution;
 unsigned int ac_prediction;
 unsigned int hec_interval;
 unsigned int data_partition;
 unsigned int short_header;
 unsigned int rvlc_enable;
};

struct venc_h263_config {
 unsigned int profile;
 unsigned int level;
};

struct venc_h264_config {
 unsigned int profile;
 unsigned int level;
 unsigned int max_nal;
 unsigned int idr_period;
};

struct venc_pmem {
 int src;
 int fd;
 unsigned int offset;
 void *virt;
 void *phys;
 unsigned int size;
};

struct venc_buffer {
 unsigned char *ptr_buffer;
 unsigned int size;
 unsigned int len;
 unsigned int offset;
 long long time_stamp;
 unsigned int flags;
 unsigned int client_data;

};

struct venc_buffers {
 struct venc_pmem recon_buf[VENC_MAX_RECON_BUFFERS];
 struct venc_pmem wb_buf;
 struct venc_pmem cmd_buf;
 struct venc_pmem vlc_buf;
};

struct venc_buffer_flush {
 unsigned int flush_mode;
};

union venc_msg_data {
 struct venc_buffer buf;
 struct venc_buffer_flush flush_ret;

};

struct venc_msg {
 unsigned int status_code;
 unsigned int msg_code;
 union venc_msg_data msg_data;
 unsigned int msg_data_size;
};

union venc_codec_config {
 struct venc_mpeg4_config mpeg4_params;
 struct venc_h263_config h263_params;
 struct venc_h264_config h264_params;
};

struct venc_q6_config {
 struct venc_common_config config_params;
 union venc_codec_config codec_params;
 struct venc_nonio_buf_config buf_params;
 void *callback_event;
};

struct venc_hdr_config {
 struct venc_common_config config_params;
 union venc_codec_config codec_params;
};

struct venc_init_config {
 struct venc_q6_config q6_config;
 struct venc_buffers q6_bufs;
};

struct venc_seq_config {
 int size;
 struct venc_pmem buf;
 struct venc_q6_config q6_config;
};

#define VENC_IOCTL_MAGIC 'V'

#define VENC_IOCTL_CMD_READ_NEXT_MSG   _IOWR(VENC_IOCTL_MAGIC, 1, struct venc_msg)

#define VENC_IOCTL_CMD_STOP_READ_MSG _IO(VENC_IOCTL_MAGIC, 2)

#define VENC_IOCTL_SET_INPUT_BUFFER   _IOW(VENC_IOCTL_MAGIC, 3, struct venc_pmem)

#define VENC_IOCTL_SET_OUTPUT_BUFFER   _IOW(VENC_IOCTL_MAGIC, 4, struct venc_pmem)

#define VENC_IOCTL_CMD_START _IOW(VENC_IOCTL_MAGIC, 5, struct venc_init_config)

#define VENC_IOCTL_CMD_ENCODE_FRAME   _IOW(VENC_IOCTL_MAGIC, 6, struct venc_buffer)

#define VENC_IOCTL_CMD_FILL_OUTPUT_BUFFER   _IOW(VENC_IOCTL_MAGIC, 7, struct venc_buffer)

#define VENC_IOCTL_CMD_FLUSH   _IOW(VENC_IOCTL_MAGIC, 8, struct venc_buffer_flush)

#define VENC_IOCTL_CMD_PAUSE _IO(VENC_IOCTL_MAGIC, 9)

#define VENC_IOCTL_CMD_RESUME _IO(VENC_IOCTL_MAGIC, 10)

#define VENC_IOCTL_CMD_STOP _IO(VENC_IOCTL_MAGIC, 11)

#define VENC_IOCTL_SET_INTRA_PERIOD   _IOW(VENC_IOCTL_MAGIC, 12, int)

#define VENC_IOCTL_CMD_REQUEST_IFRAME _IO(VENC_IOCTL_MAGIC, 13)

#define VENC_IOCTL_GET_SEQUENCE_HDR   _IOWR(VENC_IOCTL_MAGIC, 14, struct venc_seq_config)

#define VENC_IOCTL_SET_INTRA_REFRESH   _IOW(VENC_IOCTL_MAGIC, 15, int)

#define VENC_IOCTL_SET_FRAME_RATE   _IOW(VENC_IOCTL_MAGIC, 16, struct venc_frame_rate)

#define VENC_IOCTL_SET_TARGET_BITRATE   _IOW(VENC_IOCTL_MAGIC, 17, int)

#define VENC_IOCTL_SET_QP_RANGE   _IOW(VENC_IOCTL_MAGIC, 18, struct venc_qp_range)

#endif
