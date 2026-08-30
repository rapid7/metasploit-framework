/* Ruby/SerialPort $Id: serialport.c,v 1.1.1.1 2004/05/25 20:41:09 vjt Exp $
 * Guillaume Pierronnet <moumar@netcourrier.com>
 * Alan Stern <stern@rowland.harvard.edu>
 *
 * This code is hereby licensed for public consumption under either the
 * GNU GPL v2 or greater.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * For documentation on serial programming, see the excellent:
 * "Serial Programming Guide for POSIX Operating Systems"
 * written Michael R. Sweet.
 * http://www.easysw.com/~mike/serial/
 */

#define VERSION 	"0.6.1-msf"

#include <ruby.h>    /* ruby inclusion */
#include <rubyio.h>  /* ruby io inclusion */

struct modem_params {
  int data_rate;
  int data_bits;
  int stop_bits;
  int parity;
  };

struct line_signals {
  int rts;
  int dtr;
  int cts;
  int dsr;
  int dcd;
  int ri;
  };

VALUE cSerialPort; /* serial port class */

static VALUE sBaud, sDataBits, sStopBits, sParity; /* strings */
static VALUE sRts, sDtr, sCts, sDsr, sDcd, sRi;


#if defined(mswin) || defined(bccwin)


#include <stdio.h>   /* Standard input/output definitions */
#include <io.h>      /* Low-level I/O definitions */
#include <fcntl.h>   /* File control definitions */
#include <windows.h> /* Windows standard function definitions */

#define NONE            0
#define HARD            1
#define SOFT            2

#define SPACE           SPACEPARITY
#define MARK            MARKPARITY
#define EVEN            EVENPARITY
#define ODD             ODDPARITY

static char sGetCommState[] = "GetCommState";
static char sSetCommState[] = "SetCommState";
static char sGetCommTimeouts[] = "GetCommTimeouts";
static char sSetCommTimeouts[] = "SetCommTimeouts";


static HANDLE sp_get_handle(obj)
  VALUE obj;
{
  OpenFile *fptr;

  GetOpenFile(obj, fptr);
  return (HANDLE) _get_osfhandle(fileno(fptr->f));
}

static VALUE sp_create(class, _port)
  VALUE class, _port;
{
  OpenFile *fp;
  int fd;
  HANDLE fh;
  int num_port;
  char *port;
  char *ports[] = {
  "COM1", "COM2", "COM3", "COM4",
  "COM5", "COM6", "COM7", "COM8"
  };
  DCB dcb;

  NEWOBJ(sp, struct RFile);
  rb_secure(4);
  OBJSETUP(sp, class, T_FILE);
  MakeOpenFile(sp, fp);

  switch(TYPE(_port)) {
    case T_FIXNUM:
      num_port = FIX2INT(_port);
      if (num_port < 0 || num_port > sizeof(ports) / sizeof(ports[0]))
	rb_raise(rb_eArgError, "illegal port number");
      port = ports[num_port];
      break;

    case T_STRING:
      Check_SafeStr(_port);
      port = RSTRING(_port)->ptr;
      break;

    default:
      rb_raise(rb_eTypeError, "wrong argument type");
      break;
  }

  fd = open(port, O_BINARY | O_RDWR);
  if (fd == -1)
    rb_sys_fail(port);
  fh = (HANDLE) _get_osfhandle(fd);
  if (SetupComm(fh, 1024, 1024) == 0) {
    close(fd);
    rb_raise(rb_eArgError, "not a serial port");
  }

  dcb.DCBlength = sizeof(dcb);
  if (GetCommState(fh, &dcb) == 0) {
    close(fd);
    rb_sys_fail(sGetCommState);
  }
  dcb.fBinary = TRUE;
  dcb.fParity = FALSE;
  dcb.fOutxDsrFlow = FALSE;
  dcb.fDtrControl = DTR_CONTROL_ENABLE;
  dcb.fDsrSensitivity = FALSE;
  dcb.fTXContinueOnXoff = FALSE;
  dcb.fErrorChar = FALSE;
  dcb.fNull = FALSE;
  dcb.fAbortOnError = FALSE;
  dcb.XonChar = 17;
  dcb.XoffChar = 19;
  if (SetCommState(fh, &dcb) == 0) {
    close(fd);
    rb_sys_fail(sSetCommState);
  }

  fp->f = rb_fdopen(fd, "rb+");
  fp->mode = FMODE_READWRITE | FMODE_BINMODE | FMODE_SYNC;
  return (VALUE) sp;
}

static VALUE sp_set_modem_params(argc, argv, self)
  int argc;
  VALUE *argv, self;
{
  HANDLE fh;
  DCB dcb;
  VALUE _data_rate = 0, _data_bits = 0, _parity = NONE, _stop_bits = 0;
  int use_hash = 0;
  int data_rate, data_bits, parity;

  if (argc == 0)
    return self;
  if (argc == 1 && T_HASH == TYPE(argv[0])) {
    use_hash = 1;
    _data_rate = rb_hash_aref(argv[0], sBaud);
    _data_bits = rb_hash_aref(argv[0], sDataBits);
    _stop_bits = rb_hash_aref(argv[0], sStopBits);
    _parity = rb_hash_aref(argv[0], sParity);
  }

  fh = sp_get_handle(self);
  dcb.DCBlength = sizeof(dcb);
  if (GetCommState(fh, &dcb) == 0)
    rb_sys_fail(sGetCommState);

  if (!use_hash)
    _data_rate = argv[0];
  if (NIL_P(_data_rate))
    goto SkipDataRate;
  Check_Type(_data_rate, T_FIXNUM);

  data_rate = FIX2INT(_data_rate);
  switch (data_rate) {
    case 110:
    case 300:
    case 600:
    case 1200:
    case 2400:
    case 4800:
    case 9600:
    case 14400:
    case 19200:
    case 38400:
    case 56000:
    case 57600:
    case 115200:
    case 128000:
    case 256000:
      dcb.BaudRate = data_rate;
      break;

    default:
      rb_raise(rb_eArgError, "unknown baud rate");
      break;
  }
SkipDataRate:

  if (!use_hash)
    _data_bits = (argc >= 2 ? argv[1] : INT2FIX(8));
  if (NIL_P(_data_bits))
    goto SkipDataBits;
  Check_Type(_data_bits, T_FIXNUM);

  data_bits = FIX2INT(_data_bits);
  if (4 <= data_bits && data_bits <= 8)
    dcb.ByteSize = data_bits;
  else
    rb_raise(rb_eArgError, "unknown character size");
SkipDataBits:

  if (!use_hash)
    _stop_bits = (argc >= 3 ? argv[2] : INT2FIX(1));
  if (NIL_P(_stop_bits))
    goto SkipStopBits;
  Check_Type(_stop_bits, T_FIXNUM);

  switch (FIX2INT(_stop_bits)) {
    case 1:
      dcb.StopBits = ONESTOPBIT;
      break;
    case 2:
      dcb.StopBits = TWOSTOPBITS;
      break;
    default:
      rb_raise(rb_eArgError, "unknown number of stop bits");
    break;
  }
SkipStopBits:

  if (!use_hash)
    _parity = (argc >= 4 ? argv[3] : (dcb.ByteSize == 8 ?
      INT2FIX(NOPARITY) : INT2FIX(EVENPARITY)));
  if (NIL_P(_parity))
    goto SkipParity;
  Check_Type(_parity, T_FIXNUM);

  parity = FIX2INT(_parity);
  switch (parity) {
    case EVENPARITY:
    case ODDPARITY:
    case MARKPARITY:
    case SPACEPARITY:
    case NOPARITY:
      dcb.Parity = parity;
      break;

    default:
      rb_raise(rb_eArgError, "unknown parity");
      break;
  }
SkipParity:

  if (SetCommState(fh, &dcb) == 0)
    rb_sys_fail(sSetCommState);
  return self;
}

static void get_modem_params(self, mp)
  VALUE self;
  struct modem_params *mp;
{
  HANDLE fh;
  DCB dcb;

  fh = sp_get_handle(self);
  dcb.DCBlength = sizeof(dcb);
  if (GetCommState(fh, &dcb) == 0)
    rb_sys_fail(sGetCommState);

  mp->data_rate = dcb.BaudRate;
  mp->data_bits = dcb.ByteSize;
  mp->stop_bits = (dcb.StopBits == ONESTOPBIT ? 1 : 2);
  mp->parity = dcb.Parity;
}

static VALUE sp_set_flow_control(self, val)
  VALUE self, val;
{
  HANDLE fh;
  int flowc;
  DCB dcb;

  Check_Type(val, T_FIXNUM);

  fh = sp_get_handle(self);
  dcb.DCBlength = sizeof(dcb);
  if (GetCommState(fh, &dcb) == 0)
    rb_sys_fail(sGetCommState);

  flowc = FIX2INT(val);
  if (flowc & HARD) {
    dcb.fRtsControl = RTS_CONTROL_HANDSHAKE;
    dcb.fOutxCtsFlow = TRUE;
  } else {
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fOutxCtsFlow = FALSE;
  }
  if (flowc & SOFT)
    dcb.fOutX = dcb.fInX = TRUE;
  else
    dcb.fOutX = dcb.fInX = FALSE;

  if (SetCommState(fh, &dcb) == 0)
    rb_sys_fail(sSetCommState);
  return self;
}

static VALUE sp_get_flow_control(self)
  VALUE self;
{
  HANDLE fh;
  int ret;
  DCB dcb;

  fh = sp_get_handle(self);
  dcb.DCBlength = sizeof(dcb);
  if (GetCommState(fh, &dcb) == 0)
    rb_sys_fail(sGetCommState);

  ret = 0;
  if (dcb.fOutxCtsFlow)
    ret += HARD;
  if (dcb.fOutX)
    ret += SOFT;

  return INT2FIX(ret);
}

static VALUE sp_set_input_type(self, val)
{
  rb_notimplement();
  return self;
}

static VALUE sp_get_input_type(self)
{
  rb_notimplement();
  return self;
}

static VALUE sp_set_output_type(self, val)
{
  rb_notimplement();
  return self;
}

static VALUE sp_get_output_type(self)
{
  rb_notimplement();
  return self;
}

static VALUE sp_set_nonblock(self, val)
{
  rb_notimplement();
  return self;
}

static VALUE sp_get_nonblock(self)
{
  rb_notimplement();
  return self;
}

static VALUE sp_set_read_timeout(self, val)
  VALUE self, val;
{
  int timeout;
  HANDLE fh;
  COMMTIMEOUTS ctout;

  Check_Type(val, T_FIXNUM);
  timeout = FIX2INT(val);

  fh = sp_get_handle(self);
  if (GetCommTimeouts(fh, &ctout) == 0)
    rb_sys_fail(sGetCommTimeouts);

  if (timeout < 0) {
    ctout.ReadIntervalTimeout = MAXDWORD;
    ctout.ReadTotalTimeoutMultiplier = 0;
    ctout.ReadTotalTimeoutConstant = 0;
  } else if (timeout == 0) {
    ctout.ReadIntervalTimeout = MAXDWORD;
    ctout.ReadTotalTimeoutMultiplier = MAXDWORD;
    ctout.ReadTotalTimeoutConstant = MAXDWORD - 1;
  } else {
    ctout.ReadIntervalTimeout = timeout;
    ctout.ReadTotalTimeoutMultiplier = 0;
    ctout.ReadTotalTimeoutConstant = timeout;
  }

  if (SetCommTimeouts(fh, &ctout) == 0)
    rb_sys_fail(sSetCommTimeouts);
  return self;
}

static VALUE sp_get_read_timeout(self)
  VALUE self;
{
  HANDLE fh;
  COMMTIMEOUTS ctout;

  fh = sp_get_handle(self);
  if (GetCommTimeouts(fh, &ctout) == 0)
    rb_sys_fail(sGetCommTimeouts);
  switch (ctout.ReadTotalTimeoutConstant) {
    case 0:
      return INT2FIX(-1);
    case MAXDWORD:
      return INT2FIX(0);
  }
  return INT2FIX(ctout.ReadTotalTimeoutConstant);
}

static VALUE sp_set_write_timeout(self, val)
  VALUE self, val;
{
  int timeout;
  HANDLE fh;
  COMMTIMEOUTS ctout;

  Check_Type(val, T_FIXNUM);
  timeout = FIX2INT(val);

  fh = sp_get_handle(self);
  if (GetCommTimeouts(fh, &ctout) == 0)
    rb_sys_fail(sGetCommTimeouts);

  if (timeout <= 0) {
    ctout.WriteTotalTimeoutMultiplier = 0;
    ctout.WriteTotalTimeoutConstant = 0;
  } else {
    ctout.WriteTotalTimeoutMultiplier = timeout;
    ctout.WriteTotalTimeoutConstant = 0;
  }

  if (SetCommTimeouts(fh, &ctout) == 0)
    rb_sys_fail(sSetCommTimeouts);
  return self;
}

static VALUE sp_get_write_timeout(self)
  VALUE self;
{
  HANDLE fh;
  COMMTIMEOUTS ctout;

  fh = sp_get_handle(self);
  if (GetCommTimeouts(fh, &ctout) == 0)
    rb_sys_fail(sGetCommTimeouts);
  return INT2FIX(ctout.WriteTotalTimeoutMultiplier);
}

static void delay_ms(time)
  int time;
{
  HANDLE ev;

  ev = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (!ev)
    rb_sys_fail("CreateEvent");
  if (WaitForSingleObject(ev, time) == WAIT_FAILED)
    rb_sys_fail("WaitForSingleObject");
  CloseHandle(ev);
}

static VALUE sp_break(self, time)
  VALUE self, time;
{
  HANDLE fh;

  Check_Type(time, T_FIXNUM);

  fh = sp_get_handle(self);
  if (SetCommBreak(fh) == 0)
    rb_sys_fail("SetCommBreak");
  delay_ms(FIX2INT(time) * 100);
  ClearCommBreak(fh);
  return Qnil;
}

static void get_line_signals(obj, ls)
  VALUE obj;
  struct line_signals *ls;
{
  HANDLE fh;
  int status;

  fh = sp_get_handle(obj);
  if (GetCommModemStatus(fh, &status) == 0)
    rb_sys_fail("GetCommModemStatus");

  ls->cts = (status & MS_CTS_ON ? 1 : 0);
  ls->dsr = (status & MS_DSR_ON ? 1 : 0);
  ls->dcd = (status & MS_RLSD_ON ? 1 : 0);
  ls->ri = (status & MS_RING_ON ? 1 : 0);
}

static VALUE set_signal(obj, val, sigoff, sigon)
  VALUE obj,val;
  int sigoff, sigon;
{
  HANDLE fh;
  int set, sig;

  Check_Type(val, T_FIXNUM);
  fh = sp_get_handle(obj);

  set = FIX2INT(val);
  if (set == 0)
    sig = sigoff;
  else if (set == 1)
    sig = sigon;
  else
    rb_raise(rb_eArgError, "invalid value");

  if (EscapeCommFunction(fh, sig) == 0)
    rb_sys_fail("EscapeCommFunction");
  return obj;
}

static VALUE sp_set_rts(self, val)
  VALUE self, val;
{
  return set_signal(self, val, CLRRTS, SETRTS);
}

static VALUE sp_set_dtr(self, val)
  VALUE self, val;
{
  return set_signal(self, val, CLRDTR, SETDTR);
}

static VALUE sp_get_rts(self)
  VALUE self;
{
  rb_notimplement();
  return self;
}

static VALUE sp_get_dtr(self)
  VALUE self;
{
  rb_notimplement();
  return self;
}


#else /* defined(mswin) || defined(bccwin) */


#include <stdio.h>   /* Standard input/output definitions */
#include <unistd.h>  /* UNIX standard function definitions */
#include <fcntl.h>   /* File control definitions */
#include <errno.h>   /* Error number definitions */
#include <termios.h> /* POSIX terminal control definitions */
#include <sys/ioctl.h>

#ifdef CRTSCTS
#define HAVE_FLOWCONTROL_HARD 1
#else
#undef HAVE_FLOWCONTROL_HARD
#endif

#define NONE            0
#define HARD            1
#define SOFT            2

#define SPACE           0
#define MARK            0
#define EVEN            1
#define ODD             2

#define PROCESSED	1
#define RAW		2

static char sTcgetattr[] = "tcgetattr";
static char sTcsetattr[] = "tcsetattr";
static char sIoctl[] = "ioctl";
static char sFcntl[] = "fcntl";


static int sp_get_fd(obj)
  VALUE obj;
{
  OpenFile *fptr;

  GetOpenFile(obj, fptr);
  return (fileno(fptr->f));
}

static VALUE sp_create(class, _port)
  VALUE class, _port;
{
  OpenFile *fp;
  int fd;
  int num_port;
  char *port;
  char *ports[] = {
#if defined(linux) || defined(cygwin)
  "/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3",
  "/dev/ttyS4", "/dev/ttyS5", "/dev/ttyS6", "/dev/ttyS7"
#elif defined(freebsd) || defined(netbsd) || defined(openbsd)
  "/dev/cuaa0", "/dev/cuaa1", "/dev/cuaa2", "/dev/cuaa3",
  "/dev/cuaa4", "/dev/cuaa5", "/dev/cuaa6", "/dev/cuaa7"
#elif defined(solaris)
  "/dev/ttya", "/dev/ttyb", "/dev/ttyc", "/dev/ttyd",
  "/dev/ttye", "/dev/ttyf", "/dev/ttyg", "/dev/ttyh"
#elif defined(aix)
  "/dev/tty0", "/dev/tty1", "/dev/tty2", "/dev/tty3",
  "/dev/tty4", "/dev/tty5", "/dev/tty6", "/dev/tty7"
#elif defined(irix)
  "/dev/ttyf1", "/dev/ttyf2", "/dev/ttyf3", "/dev/ttyf4",
  "/dev/ttyf5", "/dev/ttyf6", "/dev/ttyf7", "/dev/ttyf8"
#endif
  };
  struct termios params;

  NEWOBJ(sp, struct RFile);
  rb_secure(4);
  OBJSETUP(sp, class, T_FILE);
  MakeOpenFile((VALUE)sp, fp);

  switch(TYPE(_port)) {
    case T_FIXNUM:
      num_port = FIX2INT(_port);
      if (num_port < 0 || num_port > sizeof(ports) / sizeof(ports[0]))
	rb_raise(rb_eArgError, "illegal port number");
      port = ports[num_port];
      break;

    case T_STRING:
      Check_SafeStr(_port);
      port = RSTRING(_port)->ptr;
      break;

    default:
      rb_raise(rb_eTypeError, "wrong argument type");
      break;
  }

  fd = open(port, O_RDWR | O_NOCTTY | O_NDELAY);
  if (fd == -1)
    rb_sys_fail(port);
  if (!isatty(fd)) {
    close(fd);
    rb_raise(rb_eArgError, "not a serial port");
  }

  if (tcgetattr(fd, &params) == -1) {
    close(fd);
    rb_sys_fail(sTcgetattr);
  }
  params.c_oflag = 0;
  params.c_lflag = 0;
  params.c_iflag &= (IXON | IXOFF | IXANY);
  params.c_cflag |= CLOCAL | CREAD;
  params.c_cflag &= ~HUPCL;
  if (tcsetattr(fd, TCSANOW, &params) == -1) {
    close(fd);
    rb_sys_fail(sTcsetattr);
  }

  fp->f = rb_fdopen(fd, "r+");
  fp->mode = FMODE_READWRITE | FMODE_SYNC;
  return (VALUE) sp;
}

static VALUE sp_set_modem_params(argc, argv, self)
  int argc;
  VALUE *argv, self;
{
  int fd;
  struct termios params;
  VALUE _data_rate = 0, _data_bits = 0, _parity = NONE, _stop_bits = 0;
  int use_hash = 0;
  int data_rate, data_bits;

  if (argc == 0)
    return self;
  if (argc == 1 && T_HASH == TYPE(argv[0])) {
    use_hash = 1;
    _data_rate = rb_hash_aref(argv[0], sBaud);
    _data_bits = rb_hash_aref(argv[0], sDataBits);
    _stop_bits = rb_hash_aref(argv[0], sStopBits);
    _parity = rb_hash_aref(argv[0], sParity);
  }

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  if (!use_hash)
    _data_rate = argv[0];
  if (NIL_P(_data_rate))
    goto SkipDataRate;
  Check_Type(_data_rate, T_FIXNUM);

  switch(FIX2INT(_data_rate)) {
    case 50:    data_rate = B50; break;
    case 75:    data_rate = B75; break;
    case 110:   data_rate = B110; break;
    case 134:   data_rate = B134; break;
    case 150:   data_rate = B150; break;
    case 200:   data_rate = B200; break;
    case 300:   data_rate = B300; break;
    case 600:   data_rate = B600; break;
    case 1200:  data_rate = B1200; break;
    case 1800:  data_rate = B1800; break;
    case 2400:  data_rate = B2400; break;
    case 4800:  data_rate = B4800; break;
    case 9600:  data_rate = B9600; break;
    case 19200: data_rate = B19200; break;
    case 38400: data_rate = B38400; break;
#ifdef B57600
    case 57600: data_rate = B57600; break;
#endif
#ifdef B76800
    case 76800: data_rate = B76800; break;
#endif
#ifdef B115200
    case 115200: data_rate = B115200; break;
#endif
#ifdef B230400
    case 230400: data_rate = B230400; break;
#endif

    default:
      rb_raise(rb_eArgError, "unknown baud rate");
      break;
  }
  cfsetispeed(&params, data_rate);
  cfsetospeed(&params, data_rate);
SkipDataRate:

  if (!use_hash)
    _data_bits = (argc >= 2 ? argv[1] : INT2FIX(8));
  if (NIL_P(_data_bits))
    goto SkipDataBits;
  Check_Type(_data_bits, T_FIXNUM);

  switch(FIX2INT(_data_bits)) {
    case 5:
      data_bits = CS5;
      break;
    case 6:
      data_bits = CS6;
      break;
    case 7:
      data_bits = CS7;
      break;
    case 8:
      data_bits = CS8;
      break;
    default:
      rb_raise(rb_eArgError, "unknown character size");
      break;
  }
  params.c_cflag &= ~CSIZE;
  params.c_cflag |= data_bits;
SkipDataBits:

  if (!use_hash)
    _stop_bits = (argc >= 3 ? argv[2] : INT2FIX(1));
  if (NIL_P(_stop_bits))
    goto SkipStopBits;
  Check_Type(_stop_bits, T_FIXNUM);

  switch(FIX2INT(_stop_bits)) {
    case 1:
      params.c_cflag &= ~CSTOPB;
      break;
    case 2:
      params.c_cflag |= CSTOPB;
      break;
    default:
      rb_raise(rb_eArgError, "unknown number of stop bits");
    break;
  }
SkipStopBits:

  if (!use_hash)
    _parity = (argc >= 4 ? argv[3] : ((params.c_cflag & CSIZE) == CS8 ?
      INT2FIX(NONE) : INT2FIX(EVEN)));
  if (NIL_P(_parity))
    goto SkipParity;
  Check_Type(_parity, T_FIXNUM);

  switch(FIX2INT(_parity)) {
    case EVEN:
      params.c_cflag |= PARENB;
      params.c_cflag &= ~PARODD;
      break;

    case ODD:
      params.c_cflag |= PARENB;
      params.c_cflag |= PARODD;
      break;

    case NONE:
      params.c_cflag &= ~PARENB;
      break;

    default:
      rb_raise(rb_eArgError, "unknown parity");
      break;
  }
SkipParity:

  if (tcsetattr(fd, TCSANOW, &params) == -1)
    rb_sys_fail(sTcsetattr);
  return self;
}

static void get_modem_params(self, mp)
  VALUE self;
  struct modem_params *mp;
{
  int fd;
  struct termios params;

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  switch (cfgetospeed(&params)) {
    case B50:    mp->data_rate = 50; break;
    case B75:    mp->data_rate = 75; break;
    case B110:   mp->data_rate = 110; break;
    case B134:   mp->data_rate = 134; break;
    case B150:   mp->data_rate = 150; break;
    case B200:   mp->data_rate = 200; break;
    case B300:   mp->data_rate = 300; break;
    case B600:   mp->data_rate = 600; break;
    case B1200:  mp->data_rate = 1200; break;
    case B1800:  mp->data_rate = 1800; break;
    case B2400:  mp->data_rate = 2400; break;
    case B4800:  mp->data_rate = 4800; break;
    case B9600:  mp->data_rate = 9600; break;
    case B19200: mp->data_rate = 19200; break;
    case B38400: mp->data_rate = 38400; break;
#ifdef B57600
    case B57600: mp->data_rate = 57600; break;
#endif
#ifdef B76800
    case B76800: mp->data_rate = 76800; break;
#endif
#ifdef B115200
    case B115200: mp->data_rate = 115200; break;
#endif
#ifdef B230400
    case B230400: mp->data_rate = 230400; break;
#endif
  }

  switch(params.c_cflag & CSIZE) {
    case CS5:
      mp->data_bits = 5;
      break;
    case CS6:
      mp->data_bits = 6;
      break;
    case CS7:
      mp->data_bits = 7;
      break;
    case CS8:
      mp->data_bits = 8;
      break;
    default:
      mp->data_bits = 0;
      break;
  }

  mp->stop_bits = (params.c_cflag & CSTOPB ? 2 : 1);

  if (!(params.c_cflag & PARENB))
    mp->parity = NONE;
  else if (params.c_cflag & PARODD)
    mp->parity = ODD;
  else
    mp->parity = EVEN;
}

static VALUE sp_set_flow_control(self, val)
  VALUE self, val;
{
  int fd;
  int flowc;
  struct termios params;

  Check_Type(val, T_FIXNUM);

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  flowc = FIX2INT(val);
  if (flowc & HARD)
#ifdef HAVE_FLOWCONTROL_HARD
    params.c_cflag |= CRTSCTS;
  else
    params.c_cflag &= ~CRTSCTS;
#else
    rb_raise(rb_eIOError, "Hardware flow control not supported");
#endif
  if (flowc & SOFT)
    params.c_iflag |= (IXON | IXOFF | IXANY);
  else
    params.c_iflag &= ~(IXON | IXOFF | IXANY);

  if (tcsetattr(fd, TCSANOW, &params) == -1)
    rb_sys_fail(sTcsetattr);
  return self;
}

static VALUE sp_get_flow_control(self)
  VALUE self;
{
  int ret;
  int fd;
  struct termios params;

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  ret = 0;
#ifdef HAVE_FLOWCONTROL_HARD
  if (params.c_cflag & CRTSCTS)
    ret += HARD;
#endif
  if (params.c_iflag & (IXON | IXOFF | IXANY))
    ret += SOFT;

  return INT2FIX(ret);
}

static VALUE sp_set_input_type(self, val)
  VALUE self, val;
{
  int fd;
  int type;
  struct termios params;

  Check_Type(val, T_FIXNUM);

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  type = FIX2INT(val);
  if (type == PROCESSED)
    params.c_lflag |= ICANON;
  else
    params.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

  if (tcsetattr(fd, TCSANOW, &params) == -1)
    rb_sys_fail(sTcsetattr);

  return self;
}

static VALUE sp_get_input_type(self)
  VALUE self;
{
  int ret;
  int fd;
  struct termios params;

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  ret = 0;
  if (params.c_lflag & ICANON)
    ret = PROCESSED;
  else
    ret = RAW;

  return INT2FIX(ret);
}

static VALUE sp_set_output_type(self, val)
  VALUE self, val;
{
  int fd;
  int type;
  struct termios params;

  Check_Type(val, T_FIXNUM);

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  type = FIX2INT(val);
  if (type == PROCESSED)
    params.c_oflag |= OPOST;
  else
    params.c_oflag &= ~OPOST;

  if (tcsetattr(fd, TCSANOW, &params) == -1)
    rb_sys_fail(sTcsetattr);

  return self;
}

static VALUE sp_get_output_type(self)
  VALUE self;
{
  int ret;
  int fd;
  struct termios params;

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  ret = 0;
  if (params.c_oflag & OPOST)
    ret = PROCESSED;
  else
    ret = RAW;

  return INT2FIX(ret);
}

static VALUE sp_set_nonblock(self, val)
  VALUE self, val;
{
  int fd;
  int flags;

  fd = sp_get_fd(self);

  flags = fcntl(fd, F_GETFL, 0);
  if(flags == -1)
    rb_sys_fail(sFcntl);

  if (val == Qtrue) {
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
      rb_sys_fail(sFcntl);
  }
  else if (val == Qfalse) {
    if(fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
      rb_sys_fail(sFcntl);
  }
  else
    rb_raise(rb_eArgError, "invalid value");

  return self;
}

static VALUE sp_get_nonblock(self)
  VALUE self;
{
  int fd;
  int flags;

  fd = sp_get_fd(self);
  flags = fcntl(fd, F_GETFL, 0);
  if(flags == -1)
    rb_sys_fail(sFcntl);

  return (flags & O_NONBLOCK) ? Qtrue : Qfalse;
}

static VALUE sp_set_read_timeout(self, val)
  VALUE self, val;
{
  int timeout;
  int fd;
  struct termios params;

  Check_Type(val, T_FIXNUM);
  timeout = FIX2INT(val);

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);

  if (timeout < 0) {
    params.c_cc[VTIME] = 0;
    params.c_cc[VMIN] = 0;
  } else if (timeout == 0) {
    params.c_cc[VTIME] = 0;
    params.c_cc[VMIN] = 1;
  } else {
    params.c_cc[VTIME] = (timeout + 50) / 100;
    params.c_cc[VMIN] = 0;
  }

  if (tcsetattr(fd, TCSANOW, &params) == -1)
    rb_sys_fail(sTcsetattr);
  return self;
}

static VALUE sp_get_read_timeout(self)
  VALUE self;
{
  int fd;
  struct termios params;

  fd = sp_get_fd(self);
  if (tcgetattr(fd, &params) == -1)
    rb_sys_fail(sTcgetattr);
  if (params.c_cc[VTIME] == 0 && params.c_cc[VMIN] == 0)
    return INT2FIX(-1);
  return INT2FIX(params.c_cc[VTIME] * 100);
}

static VALUE sp_set_write_timeout(self, val)
  VALUE self, val;
{
  rb_notimplement();
  return self;
}

static VALUE sp_get_write_timeout(self)
  VALUE self;
{
  rb_notimplement();
  return self;
}

static VALUE sp_break(self, time)
  VALUE self, time;
{
  int fd;

  Check_Type(time, T_FIXNUM);

  fd = sp_get_fd(self);
  if (tcsendbreak(fd, FIX2INT(time) / 3) == -1)
    rb_sys_fail("tcsendbreak");
  return Qnil;
}

static void get_line_signals(obj, ls)
  VALUE obj;
  struct line_signals *ls;
{
  int fd, status;

  fd = sp_get_fd(obj);
  if (ioctl(fd, TIOCMGET, &status) == -1)
    rb_sys_fail(sIoctl);

  ls->rts = (status & TIOCM_RTS ? 1 : 0);
  ls->dtr = (status & TIOCM_DTR ? 1 : 0);
  ls->cts = (status & TIOCM_CTS ? 1 : 0);
  ls->dsr = (status & TIOCM_DSR ? 1 : 0);
  ls->dcd = (status & TIOCM_CD ? 1 : 0);
  ls->ri = (status & TIOCM_RI ? 1 : 0);
}

static VALUE set_signal(obj, val, sig)
  VALUE obj,val;
  int sig;
{
  int status;
  int fd;
  int set;

  Check_Type(val, T_FIXNUM);
  fd = sp_get_fd(obj);
  if (ioctl(fd, TIOCMGET, &status) == -1)
    rb_sys_fail(sIoctl);

  set = FIX2INT(val);
  if (set == 0)
    status &= ~sig;
  else if (set == 1)
    status |= sig;
  else
    rb_raise(rb_eArgError, "invalid value");

  if (ioctl(fd, TIOCMSET, &status) == -1)
    rb_sys_fail(sIoctl);
  return obj;
}

static VALUE sp_set_rts(self, val)
  VALUE self, val;
{
    return set_signal(self, val, TIOCM_RTS);
}

static VALUE sp_set_dtr(self, val)
  VALUE self, val;
{
  return set_signal(self, val, TIOCM_DTR);
}

static VALUE sp_get_rts(self)
  VALUE self;
{
  struct line_signals ls;

  get_line_signals(self, &ls);
  return INT2FIX(ls.rts);
}

static VALUE sp_get_dtr(self)
  VALUE self;
{
  struct line_signals ls;

  get_line_signals(self, &ls);
  return INT2FIX(ls.dtr);
}


#endif /* defined(mswin) || defined(bccwin) */


static VALUE sp_set_data_rate(self, data_rate)
  VALUE self, data_rate;
{
  VALUE argv[4];

  argv[0] = data_rate;
  argv[1] = argv[2] = argv[3] = Qnil;
  return sp_set_modem_params(4, argv, self);
}

static VALUE sp_set_data_bits(self, data_bits)
  VALUE self, data_bits;
{
  VALUE argv[4];

  argv[1] = data_bits;
  argv[0] = argv[2] = argv[3] = Qnil;
  return sp_set_modem_params(4, argv, self);
}

static VALUE sp_set_stop_bits(self, stop_bits)
  VALUE self, stop_bits;
{
  VALUE argv[4];

  argv[2] = stop_bits;
  argv[0] = argv[1] = argv[3] = Qnil;
  return sp_set_modem_params(4, argv, self);
}

static VALUE sp_set_parity(self, parity)
  VALUE self, parity;
{
  VALUE argv[4];

  argv[3] = parity;
  argv[0] = argv[1] = argv[2] = Qnil;
  return sp_set_modem_params(4, argv, self);
}

static VALUE sp_get_data_rate(self)
  VALUE self;
{
  struct modem_params mp;

  get_modem_params(self, &mp);
  return INT2FIX(mp.data_rate);
}

static VALUE sp_get_data_bits(self)
  VALUE self;
{
  struct modem_params mp;

  get_modem_params(self, &mp);
  return INT2FIX(mp.data_bits);
}

static VALUE sp_get_stop_bits(self)
  VALUE self;
{
  struct modem_params mp;

  get_modem_params(self, &mp);
  return INT2FIX(mp.stop_bits);
}

static VALUE sp_get_parity(self)
  VALUE self;
{
  struct modem_params mp;

  get_modem_params(self, &mp);
  return INT2FIX(mp.parity);
}

static VALUE sp_get_modem_params(self)
  VALUE self;
{
  struct modem_params mp;
  VALUE hash;

  get_modem_params(self, &mp);
  hash = rb_hash_new();
  rb_hash_aset(hash, sBaud, INT2FIX(mp.data_rate));
  rb_hash_aset(hash, sDataBits, INT2FIX(mp.data_bits));
  rb_hash_aset(hash, sStopBits, INT2FIX(mp.stop_bits));
  rb_hash_aset(hash, sParity, INT2FIX(mp.parity));
  return hash;
}

static VALUE sp_get_cts(self)
  VALUE self;
{
  struct line_signals ls;

  get_line_signals(self, &ls);
  return INT2FIX(ls.cts);
}

static VALUE sp_get_dsr(self)
  VALUE self;
{
  struct line_signals ls;

  get_line_signals(self, &ls);
  return INT2FIX(ls.dsr);
}

static VALUE sp_get_dcd(self)
  VALUE self;
{
  struct line_signals ls;

  get_line_signals(self, &ls);
  return INT2FIX(ls.dcd);
}

static VALUE sp_get_ri(self)
  VALUE self;
{
  struct line_signals ls;

  get_line_signals(self, &ls);
  return INT2FIX(ls.ri);
}

static VALUE
sp_signals(self)
  VALUE self;
{
  struct line_signals ls;
  VALUE hash;

  get_line_signals(self, &ls);
  hash = rb_hash_new();
#if !(defined(mswin) || defined(bccwin))
  rb_hash_aset(hash, sRts, INT2FIX(ls.rts));
  rb_hash_aset(hash, sDtr, INT2FIX(ls.dtr));
#endif
  rb_hash_aset(hash, sCts, INT2FIX(ls.cts));
  rb_hash_aset(hash, sDsr, INT2FIX(ls.dsr));
  rb_hash_aset(hash, sDcd, INT2FIX(ls.dcd));
  rb_hash_aset(hash, sRi, INT2FIX(ls.ri));
  return hash;
}

void Init_serialport() {
  sBaud = rb_str_new2("baud");
  sDataBits = rb_str_new2("data_bits");
  sStopBits = rb_str_new2("stop_bits");
  sParity = rb_str_new2("parity");
  sRts = rb_str_new2("rts");
  sDtr = rb_str_new2("dtr");
  sCts = rb_str_new2("cts");
  sDsr = rb_str_new2("dsr");
  sDcd = rb_str_new2("dcd");
  sRi = rb_str_new2("ri");

  rb_gc_register_address(&sBaud);
  rb_gc_register_address(&sDataBits);
  rb_gc_register_address(&sStopBits);
  rb_gc_register_address(&sParity);
  rb_gc_register_address(&sRts);
  rb_gc_register_address(&sDtr);
  rb_gc_register_address(&sCts);
  rb_gc_register_address(&sDsr);
  rb_gc_register_address(&sDcd);
  rb_gc_register_address(&sRi);

  cSerialPort = rb_define_class("SerialPort", rb_cIO);
  rb_define_singleton_method(cSerialPort, "create", sp_create, 1);

  rb_define_method(cSerialPort, "get_modem_params", sp_get_modem_params, 0);
  rb_define_method(cSerialPort, "set_modem_params", sp_set_modem_params, -1);
  rb_define_method(cSerialPort, "modem_params", sp_get_modem_params, 0);
  rb_define_method(cSerialPort, "modem_params=", sp_set_modem_params, -1);
  rb_define_method(cSerialPort, "baud", sp_get_data_rate, 0);
  rb_define_method(cSerialPort, "baud=", sp_set_data_rate, 1);
  rb_define_method(cSerialPort, "data_bits", sp_get_data_bits, 0);
  rb_define_method(cSerialPort, "data_bits=", sp_set_data_bits, 1);
  rb_define_method(cSerialPort, "stop_bits", sp_get_stop_bits, 0);
  rb_define_method(cSerialPort, "stop_bits=", sp_set_stop_bits, 1);
  rb_define_method(cSerialPort, "parity", sp_get_parity, 0);
  rb_define_method(cSerialPort, "parity=", sp_set_parity, 1);

  rb_define_method(cSerialPort, "flow_control=", sp_set_flow_control, 1);
  rb_define_method(cSerialPort, "flow_control", sp_get_flow_control, 0);
  rb_define_method(cSerialPort, "input_type=", sp_set_input_type, 1);
  rb_define_method(cSerialPort, "input_type", sp_get_input_type, 0);
  rb_define_method(cSerialPort, "output_type=", sp_set_output_type, 1);
  rb_define_method(cSerialPort, "output_type", sp_get_output_type, 0);

  rb_define_method(cSerialPort, "nonblock=", sp_set_nonblock, 1);
  rb_define_method(cSerialPort, "nonblock", sp_get_nonblock, 0);

  rb_define_method(cSerialPort, "read_timeout", sp_get_read_timeout, 0);
  rb_define_method(cSerialPort, "read_timeout=", sp_set_read_timeout, 1);
  rb_define_method(cSerialPort, "write_timeout", sp_get_write_timeout, 0);
  rb_define_method(cSerialPort, "write_timeout=", sp_set_write_timeout, 1);

  rb_define_method(cSerialPort, "break", sp_break, 1);

  rb_define_method(cSerialPort, "signals", sp_signals, 0);
  rb_define_method(cSerialPort, "get_signals", sp_signals, 0);
  rb_define_method(cSerialPort, "rts", sp_get_rts, 0);
  rb_define_method(cSerialPort, "rts=", sp_set_rts, 1);
  rb_define_method(cSerialPort, "dtr", sp_get_dtr, 0);
  rb_define_method(cSerialPort, "dtr=", sp_set_dtr, 1);
  rb_define_method(cSerialPort, "cts", sp_get_cts, 0);
  rb_define_method(cSerialPort, "dsr", sp_get_dsr, 0);
  rb_define_method(cSerialPort, "dcd", sp_get_dcd, 0);
  rb_define_method(cSerialPort, "ri", sp_get_ri, 0);

  rb_define_const(cSerialPort, "NONE", INT2FIX(NONE));
  rb_define_const(cSerialPort, "HARD", INT2FIX(HARD));
  rb_define_const(cSerialPort, "SOFT", INT2FIX(SOFT));

  rb_define_const(cSerialPort, "SPACE", INT2FIX(SPACE));
  rb_define_const(cSerialPort, "MARK", INT2FIX(MARK));
  rb_define_const(cSerialPort, "EVEN", INT2FIX(EVEN));
  rb_define_const(cSerialPort, "ODD", INT2FIX(ODD));

  rb_define_const(cSerialPort, "PROCESSED", INT2FIX(PROCESSED));
  rb_define_const(cSerialPort, "RAW", INT2FIX(RAW));

  rb_define_const(cSerialPort, "VERSION", rb_str_new2(VERSION));

  /* The following definitions are more easily carried out in Ruby */
  rb_eval_string(
	"class SerialPort\n"

	  "def self.new(port, *params)\n"
	    "sp = create(port)\n"
	    "begin\n"
	      "sp.set_modem_params(*params)\n"
	    "rescue\n"
	      "sp.close\n"
	      "raise\n"
	    "end\n"
	    "return sp\n"
	  "end\n"

	  "def self.open(port, *params)\n"
	    "sp = create(port)\n"
	    "begin\n"
	      "sp.set_modem_params(*params)\n"
	      "if (block_given?)\n"
		"yield sp\n"
		"sp.close\n"
		"return nil\n"
	      "end\n"
	    "rescue\n"
	      "sp.close\n"
	      "raise\n"
	    "end\n"
	    "return sp\n"
	  "end\n"

	"end\n"
  );
}
