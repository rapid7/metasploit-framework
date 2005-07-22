/*
 * Prototype for in-memory executable execution.
 *
 * Improvements that need to be made:
 *
 *    - Support passing arguments to the executable
 *    - General testing with various executables
 *
 * skape
 * mmiller@hick.org
 * 05/09/2005
 */


//
// Maps the raw contents of the supplied executable image file into the current
// process and returns the address at which the image is mapped.
//
LPVOID MapNewExecutableRaw(
		IN LPCSTR ExecutableFilePath);

//
// Maps the contents of the executable image into the new process and unmaps
// the original executable.  All necessary fixups are performed to allow the
// transfer of execution control the new executable in a seamless fashion.
//
BOOL MapNewExecutableRegionInProcess(
		IN HANDLE TargetProcessHandle,
		IN HANDLE TargetThreadHandle,
		IN LPVOID NewExecutableRawImage);
