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
#ifndef __LINUX_VIDEODEV_H
#define __LINUX_VIDEODEV_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/videodev2.h>

#define VID_TYPE_CAPTURE 1  
#define VID_TYPE_TUNER 2  
#define VID_TYPE_TELETEXT 4  
#define VID_TYPE_OVERLAY 8  
#define VID_TYPE_CHROMAKEY 16  
#define VID_TYPE_CLIPPING 32  
#define VID_TYPE_FRAMERAM 64  
#define VID_TYPE_SCALES 128  
#define VID_TYPE_MONOCHROME 256  
#define VID_TYPE_SUBCAPTURE 512  
#define VID_TYPE_MPEG_DECODER 1024  
#define VID_TYPE_MPEG_ENCODER 2048  
#define VID_TYPE_MJPEG_DECODER 4096  
#define VID_TYPE_MJPEG_ENCODER 8192  

struct video_capability
{
 char name[32];
 int type;
 int channels;
 int audios;
 int maxwidth;
 int maxheight;
 int minwidth;
 int minheight;
};

struct video_channel
{
 int channel;
 char name[32];
 int tuners;
 __u32 flags;
#define VIDEO_VC_TUNER 1  
#define VIDEO_VC_AUDIO 2  
 __u16 type;
#define VIDEO_TYPE_TV 1
#define VIDEO_TYPE_CAMERA 2
 __u16 norm;
};

struct video_tuner
{
 int tuner;
 char name[32];
 unsigned long rangelow, rangehigh;
 __u32 flags;
#define VIDEO_TUNER_PAL 1
#define VIDEO_TUNER_NTSC 2
#define VIDEO_TUNER_SECAM 4
#define VIDEO_TUNER_LOW 8  
#define VIDEO_TUNER_NORM 16  
#define VIDEO_TUNER_STEREO_ON 128  
#define VIDEO_TUNER_RDS_ON 256  
#define VIDEO_TUNER_MBS_ON 512  
 __u16 mode;
#define VIDEO_MODE_PAL 0
#define VIDEO_MODE_NTSC 1
#define VIDEO_MODE_SECAM 2
#define VIDEO_MODE_AUTO 3
 __u16 signal;
};

struct video_picture
{
 __u16 brightness;
 __u16 hue;
 __u16 colour;
 __u16 contrast;
 __u16 whiteness;
 __u16 depth;
 __u16 palette;
#define VIDEO_PALETTE_GREY 1  
#define VIDEO_PALETTE_HI240 2  
#define VIDEO_PALETTE_RGB565 3  
#define VIDEO_PALETTE_RGB24 4  
#define VIDEO_PALETTE_RGB32 5  
#define VIDEO_PALETTE_RGB555 6  
#define VIDEO_PALETTE_YUV422 7  
#define VIDEO_PALETTE_YUYV 8
#define VIDEO_PALETTE_UYVY 9  
#define VIDEO_PALETTE_YUV420 10
#define VIDEO_PALETTE_YUV411 11  
#define VIDEO_PALETTE_RAW 12  
#define VIDEO_PALETTE_YUV422P 13  
#define VIDEO_PALETTE_YUV411P 14  
#define VIDEO_PALETTE_YUV420P 15  
#define VIDEO_PALETTE_YUV410P 16  
#define VIDEO_PALETTE_PLANAR 13  
#define VIDEO_PALETTE_COMPONENT 7  
};

struct video_audio
{
 int audio;
 __u16 volume;
 __u16 bass, treble;
 __u32 flags;
#define VIDEO_AUDIO_MUTE 1
#define VIDEO_AUDIO_MUTABLE 2
#define VIDEO_AUDIO_VOLUME 4
#define VIDEO_AUDIO_BASS 8
#define VIDEO_AUDIO_TREBLE 16
#define VIDEO_AUDIO_BALANCE 32
 char name[16];
#define VIDEO_SOUND_MONO 1
#define VIDEO_SOUND_STEREO 2
#define VIDEO_SOUND_LANG1 4
#define VIDEO_SOUND_LANG2 8
 __u16 mode;
 __u16 balance;
 __u16 step;
};

struct video_clip
{
 __s32 x,y;
 __s32 width, height;
 struct video_clip *next;
};

struct video_window
{
 __u32 x,y;
 __u32 width,height;
 __u32 chromakey;
 __u32 flags;
 struct video_clip __user *clips;
 int clipcount;
#define VIDEO_WINDOW_INTERLACE 1
#define VIDEO_WINDOW_CHROMAKEY 16  
#define VIDEO_CLIP_BITMAP -1

#define VIDEO_CLIPMAP_SIZE (128 * 625)
};

struct video_capture
{
 __u32 x,y;
 __u32 width, height;
 __u16 decimation;
 __u16 flags;
#define VIDEO_CAPTURE_ODD 0  
#define VIDEO_CAPTURE_EVEN 1
};

struct video_buffer
{
 void *base;
 int height,width;
 int depth;
 int bytesperline;
};

struct video_mmap
{
 unsigned int frame;
 int height,width;
 unsigned int format;
};

struct video_key
{
 __u8 key[8];
 __u32 flags;
};

struct video_mbuf
{
 int size;
 int frames;
 int offsets[VIDEO_MAX_FRAME];
};

#define VIDEO_NO_UNIT (-1)

struct video_unit
{
 int video;
 int vbi;
 int radio;
 int audio;
 int teletext;
};

struct vbi_format {
 __u32 sampling_rate;
 __u32 samples_per_line;
 __u32 sample_format;
 __s32 start[2];
 __u32 count[2];
 __u32 flags;
#define VBI_UNSYNC 1  
#define VBI_INTERLACED 2  
};

struct video_info
{
 __u32 frame_count;
 __u32 h_size;
 __u32 v_size;
 __u32 smpte_timecode;
 __u32 picture_type;
 __u32 temporal_reference;
 __u8 user_data[256];

};

struct video_play_mode
{
 int mode;
 int p1;
 int p2;
};

struct video_code
{
 char loadwhat[16];
 int datasize;
 __u8 *data;
};

#define VIDIOCGCAP _IOR('v',1,struct video_capability)  
#define VIDIOCGCHAN _IOWR('v',2,struct video_channel)  
#define VIDIOCSCHAN _IOW('v',3,struct video_channel)  
#define VIDIOCGTUNER _IOWR('v',4,struct video_tuner)  
#define VIDIOCSTUNER _IOW('v',5,struct video_tuner)  
#define VIDIOCGPICT _IOR('v',6,struct video_picture)  
#define VIDIOCSPICT _IOW('v',7,struct video_picture)  
#define VIDIOCCAPTURE _IOW('v',8,int)  
#define VIDIOCGWIN _IOR('v',9, struct video_window)  
#define VIDIOCSWIN _IOW('v',10, struct video_window)  
#define VIDIOCGFBUF _IOR('v',11, struct video_buffer)  
#define VIDIOCSFBUF _IOW('v',12, struct video_buffer)  
#define VIDIOCKEY _IOR('v',13, struct video_key)  
#define VIDIOCGFREQ _IOR('v',14, unsigned long)  
#define VIDIOCSFREQ _IOW('v',15, unsigned long)  
#define VIDIOCGAUDIO _IOR('v',16, struct video_audio)  
#define VIDIOCSAUDIO _IOW('v',17, struct video_audio)  
#define VIDIOCSYNC _IOW('v',18, int)  
#define VIDIOCMCAPTURE _IOW('v',19, struct video_mmap)  
#define VIDIOCGMBUF _IOR('v',20, struct video_mbuf)  
#define VIDIOCGUNIT _IOR('v',21, struct video_unit)  
#define VIDIOCGCAPTURE _IOR('v',22, struct video_capture)  
#define VIDIOCSCAPTURE _IOW('v',23, struct video_capture)  
#define VIDIOCSPLAYMODE _IOW('v',24, struct video_play_mode)  
#define VIDIOCSWRITEMODE _IOW('v',25, int)  
#define VIDIOCGPLAYINFO _IOR('v',26, struct video_info)  
#define VIDIOCSMICROCODE _IOW('v',27, struct video_code)  
#define VIDIOCGVBIFMT _IOR('v',28, struct vbi_format)  
#define VIDIOCSVBIFMT _IOW('v',29, struct vbi_format)  

#define BASE_VIDIOCPRIVATE 192  

#define VID_WRITE_MPEG_AUD 0
#define VID_WRITE_MPEG_VID 1
#define VID_WRITE_OSD 2
#define VID_WRITE_TTX 3
#define VID_WRITE_CC 4
#define VID_WRITE_MJPEG 5

#define VID_PLAY_VID_OUT_MODE 0

#define VID_PLAY_GENLOCK 1

#define VID_PLAY_NORMAL 2
#define VID_PLAY_PAUSE 3
#define VID_PLAY_SINGLE_FRAME 4
#define VID_PLAY_FAST_FORWARD 5
#define VID_PLAY_SLOW_MOTION 6
#define VID_PLAY_IMMEDIATE_NORMAL 7
#define VID_PLAY_SWITCH_CHANNELS 8
#define VID_PLAY_FREEZE_FRAME 9
#define VID_PLAY_STILL_MODE 10
#define VID_PLAY_MASTER_MODE 11

#define VID_PLAY_MASTER_NONE 1
#define VID_PLAY_MASTER_VIDEO 2
#define VID_PLAY_MASTER_AUDIO 3
#define VID_PLAY_ACTIVE_SCANLINES 12

#define VID_PLAY_RESET 13
#define VID_PLAY_END_MARK 14

#endif


