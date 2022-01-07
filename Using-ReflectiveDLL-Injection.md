**Update:** This is kept here mostly for backup purposes. There is now a [reflective dll template](https://github.com/rapid7/metasploit-framework/tree/c44fb61c9a8a9be54b99a36f2c09f162fc64d261/external/source/rdll_template) available that should help you in your efforts a lot more.

## Using the ReflectiveDll loader in a metasploit module.

First, let's be clear.  I have used this exactly once, but there exists little in the way of guidance on how ReflectiveDll injection works in Framework, so I figure poor guidance is better than none.  I am in part hoping that someone who knows how it works will come along and correct this, ala Cunningham's Law.

This documentation assumes that you have some familiarity with DLLs already.

### Step 1 - Make your DLL
Use Visual studio 2013 and make a standard, empty DLL.  Do not attempt to add the reflective DLL stuff yet.
When you make the DLL, make sure that you have at least three files: A header file with the function declarations, a c(pp) file with the functions that 'do' the exploit, and a DllMain file with the `DllMain` function.  I find that testing the DLL outside the reflective loader helps tremendously, so in the header file, I declare my working function as an `extern`, C-style function:
`extern "C" __declspec (dllexport) void PrivEsc(void);`

I think using C as the language over cpp would make life marginally easier, as you can combine the source code into one project.  Using cpp meant I needed to have separate projects, or at least using my limited compiler knowledge that's how I got it to work.  I noticed OJ was able to extend his c project ([exploits/capcom_sys_exec](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/capcom_sys_exec.rb)) to include the reflectiveloader, but I could not seem to do the same for my cpp project.

Store your project in `external/source/exploits/<identifier>/<projectname>`. That's not written in stone.  The project I just finished had both DLL and EXE, so I have `external/source/exploits/<identifier>/dll` and `external/source/exploits/<identifier>/exe`.  Just don't be a jerk and do something hard to follow.  Your requirements may differ, and we're not super particular as long as it makes sense.  I suggest the identifier to make life easier, then a project name because you'll be bringing the reflective loader project into the identifier folder, and at least I like to have some separation between the two.

### Step 2  Write the DLL using an extern, C-linkage entry point to make testing easier

In this case, I was writing a privesc, so I called it `PrivEsc` because I am super-imaginative and I have done enough code maintenance that I try to be nice to the next dev.  By declaring it an external function and using C-style linkages, you can test the function independently using the `rundll32.exe` binary.

For example, if the dll were named mydll.dll, you can run the privEsc alone with the command 
`> rundll.exe mydll.dll, PrivEsc`

That way, you can isolate the behavior of the exploit before adding a payload.  Because I was using a privesc, I just made the last line of the privesc `system("cmd.exe");` so I could verify that on the target machine.  If I got a system-level cmd prompt, I won!

### Step 3 Add ReflectiveDLL Injection to it.
This is actually pretty simple.  Once your code is doing what it is supposed to do, add the ReflectiveDLL injection to it.  Move the rdi (ReflectiveDLL injection) code into your existing project and add the inject project into your solution.  Again, this worked for me and appears to be a popular choice.

When you copy the RefelctiveDLL code into your project, you are going to replace your `DllMain` file with the `ReflectiveDll.c` file.  Include the header file containing your desired entry point so that when `DllMain` gets launched, it can find your desired entry point.

I also noticed and appreciated that others structured the code into two parts: Exploit and Exploiter.  Exploiter does the heavy lifting with functions, and Exploit calls the functions and runs the shellcode after the exploit completes.  For example, I made a privesc and the code required to accomplish the elevation was bundled in a function called `PrivEsc` contained within my `Exploiter.cpp` file.  The Exploit file was very simple in comparison:

```c
#include <Windows.h>
#include "Exploit.h"
#include "Exploiter.h"

static VOID ExecutePayload(LPVOID lpPayload)
{
  VOID(*lpCode)() = (VOID(*)())lpPayload;
  lpCode();
  return;
}

VOID Exploit(LPVOID lpPayload)
{
  PrivEsc();
  ExecutePayload(lpPayload);
}
```

That `ExecutePayload` function is there to... well.... Execute the payload.  We'll talk about it later, but make sure that you have it accepting a pointer and executing it.  That'll be how we get a payload into the running thread.

All the `Exploit.cpp` needs to do is give a clear way for me to run the code I wanted to get system, then call the function responsible for starting the shellcode.  In my case, all I needed to do was to somehow run `PrivEsc` and then `ExecutePayload(pPayload)`.

Sure enough, if you check out the `ReflectiveDll.c` file, you can see that it is really straightforward and should look a lot like your previous `DllMain` function, except there's a function call in `DLL_PROCESS_ATTACH`:

```c
#include "ReflectiveLoader.h"
#include "Exploit.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
  BOOL bReturnValue = TRUE;
  switch (dwReason) {
    case DLL_QUERY_HMODULE:
      if (lpReserved != NULL)
        *(HMODULE *)lpReserved = hAppInstance;
      break;
    case DLL_PROCESS_ATTACH:
      hAppInstance = hinstDLL;
      // MessageBox(0, "In DLLMain", "Status", MB_OK);
      Exploit(lpReserved);
      break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;
  }
  return bReturnValue;
}
```

One thing to understand- despite the feelings I had reading through the framework side, you must specify the entry point for the code you want executed in `DLL_PROCESS_ATTACH`.  We are going to be (quasi) calling `DllMain`, and `DLL_PROCESS_ATTACH` will fire, thus giving us code execution in the remote process context.  As you create the rest of your code, remember that `lpReserved` from `DllMain` will contain the address of your payload.  Be sure that `lpReserve` has a clear path to your call of `ExecutePayload()`.  

Some of the output from the framework side of the injection was confusing to me because I am used to loading DLLs explicitly and implicitly, and some of the framework methods made it sound like we were not relying on DLL_PROCESS_ATTACH.  We are, but in a slightly more round-about way.  That said, remember if you go back to troubleshooting just your exploit code in the `extern` function, `DLL_PROCESS_ATTACH` will still execute if you use `rundll32.exe` to call your function.  Be sure to comment out your calls in `DLL_PROCESS_ATTACH` if you go back to debugging unless you want dueling exploits.

OK, so at this point, you've got a DLL with a function that does something you want, and even better, it compiles!  Move that binary to the data directory corresponding to the external directory you used above.  i.e. if you used `external/source/exploits/myfancyexploit`, put your binary in `data/exploits/myfancyexploit/`.  If you can automate that move as a post build step, even better!

### Now that we have the binary, we need to execute it on target- Enter Framework!

## Step 4: Adding the framework module
Once you've got the DLL working and have it compiling with ReflectiveLoader, you have to make a framework module to use it. OJ's [exploits/capcom_sys_exec](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/capcom_sys_exec.rb) is a great place to start looking as an examples; it is super easy and simple to read, so let's review:

(1) Make sure you have a handle to a process. The easiest way be able to get a handle to a process is to launch your own:
`notepad_process = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true})`

(2) We need to write to that process and launch a thread in the process, so let's get a handle to the process with ALL_ACCESS attributes:
`process = client.sys.process.open(notepad_process.pid, PROCESS_ALL_ACCESS)`

(3) Grab the path to your binary file:
`library_path = ::File.join(Msf::Config.data_directory, 'exploits', 'myfancyexploit', 'myfancyexploit.dll')`

Replace the directory and file names with the ones to your binary.

(3.5) OJ went ahead and expanded the path; likely this is because he's used filepath hijacking in the past:
`library_path = ::File.expand_path(library_path)`

(4) Now, here's where things get fun- inject your DLL directly into the memory of notepad:
`exploit_mem, offset = inject_dll_into_process(process, library_path)`

That function allocates memory in the process and loads up the DLL. There is a second method that allows you to upload DLL data, so you could create a payload using a template and load that without the dll touching the local or remote disk, but I have not had cause to use it.

Unfortunately, this is where my grasp of things gets tenuous because it departs from my experience of traditional DLL loading with LoadLibrary and GetProcAddress. We copied the DLL into the remote process memory, but we have not "loaded" it, so DLL_PROCESS_ATTACH is not executed.  That's a good thing, as we have not yet provided the payload!

I square this by basically treating it like process hollowing, but on a thread-level.  Watching OJ's ReflectiveDll injection video might help: <https://www.youtube.com/watch?v=ZKznMBWUQ_c>

You may want to watch it daily for a month or so.

Regardless, now we have a process with our exploit DLL mapped into its memory, but not doing anything.  Now we need to get the payload into the process too, so we can get exploit and payload execution.  Getting the payload in there is honestly not much different that getting the DLL data in there.  

(5) Just allocate some RWX memory and copy the shellcode over. There's a method for that:
`payload_mem = inject_into_process(process, payload.encoded)`

To be clear, That's the first time you should have dealt with the payload, because while it is annoying how much goes on in the background in Framework, when you know it is happening, Framework is awesome!

Now, if you've been paying attention to the return values from the above methods, we have three important values: (1) `exploit_mem` that has the address of the DLL loaded into memory, (2) `offset` that (I think) contains the offset to the `DllMain` function inside the DLL loaded into memory, and (3) `payload_mem`, that contains the address of your payload.

(6) Now, With those three values, and our code stored in the process's memory, things make a lot more sense.  We just need to create a thread in the process and point it to the `DllMain` function with the address of our payload as the `lpReserve` parameter.
`process.thread.create(exploit_mem + offset, payload_mem)`

(6) What I'm Still unclear about:
(6.1) How do we get the offset value?  If we check out `inject_dll_into_process`, it shows that it is searching the pe for `ReflectiveLoader` and that's not a string I can find as an entry point.  I do not understand why that gives us the offset to what I believe to be DllMain when it appears to be searching to ReflectiveLoader...?
(6.2) There are a few ways to use `ReflectiveDllLoader`, and I wish I could read more on using it as an import like OJ does in that `capcom_sys_exec`.
