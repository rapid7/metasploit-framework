#include "ruby.h"
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <tchar.h>

#ifdef HAVE_SEH_H
#include <seh.h>
#endif

#define WIN32_SERVICE_VERSION "0.7.2"

// Ruby 1.9.x
#ifndef RSTRING_PTR
#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif
#ifndef RSTRING_LEN
#define RSTRING_LEN(s) (RSTRING(s)->len)
#endif

#ifndef RARRAY_PTR
#define RARRAY_PTR(a) (RARRAY(a)->ptr)
#endif
#ifndef RARRAY_LEN
#define RARRAY_LEN(a) (RARRAY(a)->len)
#endif

static VALUE cDaemonError;

static HANDLE hThread;
static HANDLE hStartEvent;
static HANDLE hStopEvent;
static HANDLE hStopCompletedEvent;
static SERVICE_STATUS_HANDLE ssh;
static DWORD dwServiceState;
static TCHAR error[1024];
static int Argc;
static VALUE* Argv;

CRITICAL_SECTION csControlCode;
// I happen to know from looking in the header file
// that 0 is not a valid service control code
// so we will use it, the value does not matter
// as long as it will never show up in ServiceCtrl
// - Patrick Hurley
#define IDLE_CONTROL_CODE 0
static int waiting_control_code = IDLE_CONTROL_CODE;

static VALUE service_close(VALUE);
void  WINAPI Service_Main(DWORD dwArgc, LPTSTR *lpszArgv);
void  WINAPI Service_Ctrl(DWORD dwCtrlCode);
void  SetTheServiceStatus(DWORD dwCurrentState,DWORD dwWin32ExitCode,
                          DWORD dwCheckPoint,  DWORD dwWaitHint);

// Return an error code as a string
LPTSTR ErrorDescription(DWORD p_dwError)
{
  HLOCAL hLocal = NULL;
  static TCHAR ErrStr[1024];
  int len;

  if (!(len=FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER |
    FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    p_dwError,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
    (LPTSTR)&hLocal,
    0,
    NULL)))
  {
    rb_raise(rb_eStandardError, "unable to format error message");
  }
  memset(ErrStr, 0, sizeof(ErrStr));
  strncpy(ErrStr, (LPTSTR)hLocal, len-2); // remove \r\n
  LocalFree(hLocal);
  return ErrStr;
}

// Called by the service control manager after the call to
// StartServiceCtrlDispatcher.
void WINAPI Service_Main(DWORD dwArgc, LPTSTR *lpszArgv)
{
  // Obtain the name of the service.
  LPTSTR lpszServiceName = lpszArgv[0];

  // Args passed to Service.start
  if(dwArgc > 1){
    unsigned int i;
    Argc = dwArgc - 1;
    Argv = malloc(sizeof(VALUE)*Argc);

    for(i=1; i < dwArgc; i++)
      Argv[i-1] = rb_str_new2(lpszArgv[i]);
  }

  // Register the service ctrl handler.
  ssh = RegisterServiceCtrlHandler(
    lpszServiceName,
    (LPHANDLER_FUNCTION)Service_Ctrl
  );

  // no service to stop, no service handle to notify, nothing to do but exit
  if(ssh == (SERVICE_STATUS_HANDLE)0)
    return;

  // The service has started.
  SetTheServiceStatus(SERVICE_RUNNING, NO_ERROR, 0, 0);

  SetEvent(hStartEvent);

  // Main loop for the service.
  while(WaitForSingleObject(hStopEvent, 1000) != WAIT_OBJECT_0)
  {
  }

  // Main loop for the service.
  while(WaitForSingleObject(hStopCompletedEvent, 1000) != WAIT_OBJECT_0)
  {
  }

  // Stop the service.
  SetTheServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0);
}

VALUE Service_Event_Dispatch(VALUE val)
{
  VALUE func,self;
  VALUE result = Qnil;

  if(val!=Qnil) {
    self = RARRAY_PTR(val)[0];
    func = NUM2INT(RARRAY_PTR(val)[1]);

    result = rb_funcall(self,func,0);
  }

  return result;
}

VALUE Ruby_Service_Ctrl(VALUE self){
  while(WaitForSingleObject(hStopEvent,0) == WAIT_TIMEOUT){
#if !defined(__GNUC__) || defined(HAVE_SEH_H)
    __try{
#endif
      EnterCriticalSection(&csControlCode);

      // Check to see if anything interesting has been signaled
      if(waiting_control_code != IDLE_CONTROL_CODE){
        if(waiting_control_code != SERVICE_CONTROL_STOP){
          // If there is a code, create a ruby thread to deal with it
          // this might be over engineering the solution, but I don't
          // want to block Service_Ctrl longer than necessary and the
          // critical section will block it.
          VALUE EventHookHash = rb_ivar_get(self, rb_intern("@event_hooks"));

          if(EventHookHash != Qnil){
            VALUE val = rb_hash_aref(
              EventHookHash,
              INT2NUM(waiting_control_code)
            );

            if(val != Qnil)
              rb_thread_create(Service_Event_Dispatch, (void*) val);
          }
        }
        else{
          break;
        }

        waiting_control_code = IDLE_CONTROL_CODE;
      }
#if !defined(__GNUC__) || defined(HAVE_SEH_H)
    }
    __finally {
#endif
      LeaveCriticalSection(&csControlCode);
#if !defined(__GNUC__) || defined(HAVE_SEH_H)
    }
#endif
    // This is an ugly polling loop, be as polite as possible
    rb_thread_polling();
  }

  // Force service_stop call
  {
    VALUE EventHookHash = rb_ivar_get(self, rb_intern("@event_hooks"));

    if(EventHookHash != Qnil){
      VALUE val = rb_hash_aref(EventHookHash, INT2NUM(SERVICE_CONTROL_STOP));

      if(val!=Qnil)
        rb_thread_create(Service_Event_Dispatch, (void*) val);
    }
  }

  return Qnil;
}

// Handles control signals from the service control manager.
void WINAPI Service_Ctrl(DWORD dwCtrlCode)
{
  DWORD dwState = SERVICE_RUNNING;

#if !defined(__GNUC__) || defined(HAVE_SEH_H)
  __try{
#endif
    EnterCriticalSection(&csControlCode);
    waiting_control_code = dwCtrlCode;
#if !defined(__GNUC__) || defined(HAVE_SEH_H)
  }
  __finally{
#endif
    LeaveCriticalSection(&csControlCode);
#if !defined(__GNUC__) || defined(HAVE_SEH_H)
  }
#endif

  switch(dwCtrlCode)
  {
    case SERVICE_CONTROL_STOP:
      dwState = SERVICE_STOP_PENDING;
      break;
    case SERVICE_CONTROL_SHUTDOWN:
      dwState = SERVICE_STOP_PENDING;
      break;
    case SERVICE_CONTROL_PAUSE:
      dwState = SERVICE_PAUSED;
      break;
    case SERVICE_CONTROL_CONTINUE:
      dwState = SERVICE_RUNNING;
      break;
    case SERVICE_CONTROL_INTERROGATE:
      break;
    default:
      break;
  }

  // Set the status of the service.
  SetTheServiceStatus(dwState, NO_ERROR, 0, 0);

  // Tell service_main thread to stop.
  if ((dwCtrlCode == SERVICE_CONTROL_STOP) ||
     (dwCtrlCode == SERVICE_CONTROL_SHUTDOWN))
  {
    if(!SetEvent(hStopEvent))
      SetTheServiceStatus(SERVICE_STOPPED, GetLastError(), 0, 0);
  }
}

//  Wraps SetServiceStatus.
void SetTheServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode,
                         DWORD dwCheckPoint,   DWORD dwWaitHint)
{
  SERVICE_STATUS ss;  // Current status of the service.

  // Disable control requests until the service is started.
  if(dwCurrentState == SERVICE_START_PENDING){
    ss.dwControlsAccepted = 0;
  }
  else{
    ss.dwControlsAccepted =
      SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|
      SERVICE_ACCEPT_PAUSE_CONTINUE|SERVICE_ACCEPT_SHUTDOWN;
  }

  // Initialize ss structure.
  ss.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
  ss.dwServiceSpecificExitCode = 0;
  ss.dwCurrentState            = dwCurrentState;
  ss.dwWin32ExitCode           = dwWin32ExitCode;
  ss.dwCheckPoint              = dwCheckPoint;
  ss.dwWaitHint                = dwWaitHint;

  dwServiceState = dwCurrentState;

  // Send status of the service to the Service Controller.
  if(!SetServiceStatus(ssh, &ss))
    SetEvent(hStopEvent);
}

DWORD WINAPI ThreadProc(LPVOID lpParameter){
  SERVICE_TABLE_ENTRY ste[] =
    {{TEXT(""),(LPSERVICE_MAIN_FUNCTION)Service_Main}, {NULL, NULL}};

  // No service to step, no service handle, no ruby exceptions, just
  // terminate the thread.
  if(!StartServiceCtrlDispatcher(ste))
    return 1;

  return 0;
}

static VALUE daemon_allocate(VALUE klass){
  return Data_Wrap_Struct(klass, 0, 0, 0);
}

// Call service_main method
static VALUE daemon_mainloop_protect(VALUE self)
{
  if(rb_respond_to(self,rb_intern("service_main"))){
    if(Argc == 0)
      rb_funcall(self, rb_intern("service_main"), 0);
    else
      rb_funcall2(self, rb_intern("service_main"), Argc, Argv);
  }

  return self;
}

static VALUE daemon_mainloop_ensure(VALUE self)
{
  int i;

  // Signal both the ruby thread and service_main thread to terminate
  SetEvent(hStopEvent);

  // Wait for ALL ruby threads to exit
  for(i=1; TRUE; i++)
  {
    VALUE list = rb_funcall(rb_cThread, rb_intern("list"), 0);

    if(RARRAY_LEN(list) <= 1)
      break;

    // This is another ugly polling loop, be as polite as possible
    rb_thread_polling();

    SetTheServiceStatus(SERVICE_STOP_PENDING, 0, i, 1000);
  }

  // Only one ruby thread
  SetEvent(hStopCompletedEvent);

  // Wait for the thread to stop BEFORE we close the hStopEvent handle
  WaitForSingleObject(hThread, INFINITE);

  // Close the event handle, ignoring failures. We may be cleaning up
  // after an exception, so let that exception fall through.
  CloseHandle(hStopEvent);

  return self;
}

/*
 * This is the method that actually puts your code into a loop and allows it
 * to run as a service.  The code that is actually run while in the mainloop
 * is what you defined in your own Daemon#service_main method.
 */
static VALUE daemon_mainloop(VALUE self)
{
  DWORD ThreadId;
  HANDLE events[2];
  DWORD index;
  VALUE result, EventHookHash;
  int status = 0;

  dwServiceState = 0;

  // Redirect STDIN, STDOUT and STDERR to the NUL device if they're still
  // associated with a tty. This helps newbs avoid Errno::EBADF errors.
  if(rb_funcall(rb_stdin, rb_intern("isatty"), 0) == Qtrue)
    rb_funcall(rb_stdin, rb_intern("reopen"), 1, rb_str_new2("NUL"));

  if(rb_funcall(rb_stdout, rb_intern("isatty"), 0) == Qtrue)
    rb_funcall(rb_stdout, rb_intern("reopen"), 1, rb_str_new2("NUL"));

  if(rb_funcall(rb_stderr, rb_intern("isatty"), 0) == Qtrue)
    rb_funcall(rb_stderr, rb_intern("reopen"), 1, rb_str_new2("NUL"));

  // Use a markable instance variable to prevent the garbage collector
  // from freeing the hash before Ruby_Service_Ctrl exits, or just
  // at any ole time while running the service
  EventHookHash = rb_hash_new();
  rb_ivar_set(self, rb_intern("@event_hooks"), EventHookHash);

  // Event hooks
  if(rb_respond_to(self, rb_intern("service_stop"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_STOP),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_stop"))));
  }

  if(rb_respond_to(self, rb_intern("service_pause"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_PAUSE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_pause"))));
  }

  if(rb_respond_to(self, rb_intern("service_resume"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_CONTINUE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_resume"))));
  }

  if(rb_respond_to(self, rb_intern("service_interrogate"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_INTERROGATE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_interrogate"))));
  }

  if(rb_respond_to(self, rb_intern("service_shutdown"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_SHUTDOWN),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_shutdown"))));
  }

#ifdef SERVICE_CONTROL_PARAMCHANGE
  if(rb_respond_to(self, rb_intern("service_paramchange"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_PARAMCHANGE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_paramchange"))));
  }
#endif

#ifdef SERVICE_CONTROL_NETBINDADD
  if(rb_respond_to(self, rb_intern("service_netbindadd"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_NETBINDADD),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_netbindadd"))));
  }
#endif

#ifdef SERVICE_CONTROL_NETBINDREMOVE
  if(rb_respond_to(self, rb_intern("service_netbindremove"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_NETBINDREMOVE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_netbindremove"))));
  }
#endif

#ifdef SERVICE_CONTROL_NETBINDENABLE
  if(rb_respond_to(self, rb_intern("service_netbindenable"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_NETBINDENABLE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_netbindenable"))));
  }
#endif

#ifdef SERVICE_CONTROL_NETBINDDISABLE
  if(rb_respond_to(self, rb_intern("service_netbinddisable"))){
    rb_hash_aset(EventHookHash, INT2NUM(SERVICE_CONTROL_NETBINDDISABLE),
      rb_ary_new3(2, self, INT2NUM(rb_intern("service_netbinddisable"))));
  }
#endif

  // Calling init here so that init failures never even tries to
  // start the service... of course that means that init methods
  // must be very quick, because the SCM will be receiving no
  // START_PENDING messages while init's running - I may fix this
  // later
  if(rb_respond_to(self, rb_intern("service_init")))
    rb_funcall(self, rb_intern("service_init"),0);

  // Create the event to signal the service to start.
  hStartEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  if(hStartEvent == NULL)
    rb_raise(cDaemonError, ErrorDescription(GetLastError()));

  // Create the event to signal the service to stop.
  hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  if(hStopEvent == NULL)
    rb_raise(cDaemonError, ErrorDescription(GetLastError()));

  // Create the event to signal the service that stop has completed
  hStopCompletedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  if(hStopCompletedEvent == NULL)
    rb_raise(cDaemonError, ErrorDescription(GetLastError()));

  // Create Thread for service main
  hThread = CreateThread(NULL, 0, ThreadProc, 0, 0, &ThreadId);

  if(hThread == INVALID_HANDLE_VALUE)
    rb_raise(cDaemonError, ErrorDescription(GetLastError()));

  events[0] = hThread;
  events[1] = hStartEvent;

  // wait for Service_Main function to either start the service OR terminate
  while((index = WaitForMultipleObjects(2,events,FALSE,1000)) == WAIT_TIMEOUT)
  {
  }

  // thread exited, so the show is off
  if(index == WAIT_OBJECT_0)
    rb_raise(cDaemonError, "Service_Main thread exited abnormally");

  // from this point onward, stopevent must be triggered!

  // Create the green thread to poll for Service_Ctrl events
  rb_thread_create(Ruby_Service_Ctrl, (void *)self);

  result = rb_protect(daemon_mainloop_protect, self, &status);

  // service_main raised an exception
  if(status){
    daemon_mainloop_ensure(self);
    rb_jump_tag(status);
  }

  // service_main exited cleanly
  return daemon_mainloop_ensure(self);
}

/*
 * Returns the state of the service (as an constant integer) which can be any
 * of the service status constants, e.g. RUNNING, PAUSED, etc.
 *
 * This method is typically used within your service_main method to setup the
 * loop. For example:
 *
 *    class MyDaemon < Daemon
 *       def service_main
 *          while state == RUNNING || state == PAUSED || state == IDLE
 *             # Your main loop here
 *          end
 *       end
 *    end
 *
 * See the Daemon#running? method for an abstraction of the above code.
 */
static VALUE daemon_state(VALUE self){
  return UINT2NUM(dwServiceState);
}

/*
 * Returns whether or not the service is in a running state, i.e. the service
 * status is either RUNNING, PAUSED or IDLE.
 *
 * This is typically used within your service_main method to setup the main
 * loop. For example:
 *
 *    class MyDaemon < Daemon
 *       def service_main
 *          while running?
 *             # Your main loop here
 *          end
 *       end
 *    end
 */
static VALUE daemon_is_running(VALUE self){
  VALUE v_bool = Qfalse;

  if(
    (dwServiceState == SERVICE_RUNNING) ||
    (dwServiceState == SERVICE_PAUSED) ||
    (dwServiceState == 0)
  ){
    v_bool = Qtrue;
  }

  return v_bool;
}

/*
 * This is a shortcut for Daemon.new + Daemon#mainloop.
 */
static VALUE daemon_c_mainloop(VALUE klass){
  VALUE v_args[1];
  VALUE v_daemon = rb_class_new_instance(0, v_args, klass);
  return rb_funcall(v_daemon, rb_intern("mainloop"), 0, 0);
}

void Init_daemon()
{
  /* The Win32 module serves as a namespace only. */
  VALUE mWin32 = rb_define_module("Win32");

  /* The Daemon class encapsulates a Windows service through the use
   * of callback methods and a main loop.
   */
  VALUE cDaemon = rb_define_class_under(mWin32, "Daemon", rb_cObject);

  /* Error typically raised if something goes wrong with your daemon. */
  cDaemonError = rb_define_class_under(cDaemon, "Error", rb_eStandardError);

  rb_define_alloc_func(cDaemon, daemon_allocate);
  rb_define_method(cDaemon, "mainloop", daemon_mainloop, 0);
  rb_define_method(cDaemon, "state", daemon_state, 0);
  rb_define_method(cDaemon, "running?", daemon_is_running, 0);

  rb_define_singleton_method(cDaemon, "mainloop", daemon_c_mainloop, 0);

  // Intialize critical section used by green polling thread
  InitializeCriticalSection(&csControlCode);

  // Constants

  /* 0.7.2: The version of this library */
  rb_define_const(cDaemon, "VERSION", rb_str_new2(WIN32_SERVICE_VERSION));

  /* Service has received a signal to resume but is not yet running */
  rb_define_const(cDaemon, "CONTINUE_PENDING",
    INT2NUM(SERVICE_CONTINUE_PENDING));

  /* Service has received a signal to pause but is not yet paused */
  rb_define_const(cDaemon, "PAUSE_PENDING", INT2NUM(SERVICE_PAUSE_PENDING));

  /* Service is in a paused state */
  rb_define_const(cDaemon, "PAUSED", INT2NUM(SERVICE_PAUSED));

  /* Service is running */
  rb_define_const(cDaemon, "RUNNING", INT2NUM(SERVICE_RUNNING));

  /* Service has received a signal to start but is not yet running */
  rb_define_const(cDaemon, "START_PENDING", INT2NUM(SERVICE_START_PENDING));

  /* Service has received a signal to stop but has not yet stopped */
  rb_define_const(cDaemon, "STOP_PENDING", INT2NUM(SERVICE_STOP_PENDING));

  /* Service is stopped. */
  rb_define_const(cDaemon, "STOPPED", INT2NUM(SERVICE_STOPPED));

  /* Service is in an idle state */
  rb_define_const(cDaemon, "IDLE", INT2NUM(0));
}
