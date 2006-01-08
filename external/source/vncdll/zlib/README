zlib 1.1.4 is a general purpose data compression library.  All the code
is thread safe.  The data format used by the zlib library
is described by RFCs (Request for Comments) 1950 to 1952 in the files 
http://www.ietf.org/rfc/rfc1950.txt (zlib format), rfc1951.txt (deflate
format) and rfc1952.txt (gzip format). These documents are also available in
other formats from ftp://ftp.uu.net/graphics/png/documents/zlib/zdoc-index.html

All functions of the compression library are documented in the file zlib.h
(volunteer to write man pages welcome, contact jloup@gzip.org). A usage
example of the library is given in the file example.c which also tests that
the library is working correctly. Another example is given in the file
minigzip.c. The compression library itself is composed of all source files
except example.c and minigzip.c.

To compile all files and run the test program, follow the instructions
given at the top of Makefile. In short "make test; make install"
should work for most machines. For Unix: "./configure; make test; make install"
For MSDOS, use one of the special makefiles such as Makefile.msc.
For VMS, use Make_vms.com or descrip.mms.

Questions about zlib should be sent to <zlib@gzip.org>, or to
Gilles Vollant <info@winimage.com> for the Windows DLL version.
The zlib home page is http://www.zlib.org or http://www.gzip.org/zlib/
Before reporting a problem, please check this site to verify that
you have the latest version of zlib; otherwise get the latest version and
check whether the problem still exists or not.

PLEASE read the zlib FAQ http://www.gzip.org/zlib/zlib_faq.html
before asking for help.

Mark Nelson <markn@ieee.org> wrote an article about zlib for the Jan. 1997
issue of  Dr. Dobb's Journal; a copy of the article is available in
http://dogma.net/markn/articles/zlibtool/zlibtool.htm

The changes made in version 1.1.4 are documented in the file ChangeLog.
The only changes made since 1.1.3 are bug corrections:

- ZFREE was repeated on same allocation on some error conditions.
  This creates a security problem described in
  http://www.zlib.org/advisory-2002-03-11.txt
- Returned incorrect error (Z_MEM_ERROR) on some invalid data
- Avoid accesses before window for invalid distances with inflate window
  less than 32K.
- force windowBits > 8 to avoid a bug in the encoder for a window size
  of 256 bytes. (A complete fix will be available in 1.1.5).

The beta version 1.1.5beta includes many more changes. A new official
version 1.1.5 will be released as soon as extensive testing has been
completed on it.


Unsupported third party contributions are provided in directory "contrib".

A Java implementation of zlib is available in the Java Development Kit
http://www.javasoft.com/products/JDK/1.1/docs/api/Package-java.util.zip.html
See the zlib home page http://www.zlib.org for details.

A Perl interface to zlib written by Paul Marquess <pmarquess@bfsec.bt.co.uk>
is in the CPAN (Comprehensive Perl Archive Network) sites
http://www.cpan.org/modules/by-module/Compress/

A Python interface to zlib written by A.M. Kuchling <amk@magnet.com>
is available in Python 1.5 and later versions, see
http://www.python.org/doc/lib/module-zlib.html

A zlib binding for TCL written by Andreas Kupries <a.kupries@westend.com>
is availlable at http://www.westend.com/~kupries/doc/trf/man/man.html

An experimental package to read and write files in .zip format,
written on top of zlib by Gilles Vollant <info@winimage.com>, is
available at http://www.winimage.com/zLibDll/unzip.html
and also in the contrib/minizip directory of zlib.


Notes for some targets:

- To build a Windows DLL version, include in a DLL project zlib.def, zlib.rc
  and all .c files except example.c and minigzip.c; compile with -DZLIB_DLL
  The zlib DLL support was initially done by Alessandro Iacopetti and is
  now maintained by Gilles Vollant <info@winimage.com>. Check the zlib DLL
  home page at http://www.winimage.com/zLibDll

  From Visual Basic, you can call the DLL functions which do not take
  a structure as argument: compress, uncompress and all gz* functions.
  See contrib/visual-basic.txt for more information, or get
  http://www.tcfb.com/dowseware/cmp-z-it.zip

- For 64-bit Irix, deflate.c must be compiled without any optimization.
  With -O, one libpng test fails. The test works in 32 bit mode (with
  the -n32 compiler flag). The compiler bug has been reported to SGI.

- zlib doesn't work with gcc 2.6.3 on a DEC 3000/300LX under OSF/1 2.1   
  it works when compiled with cc.

- on Digital Unix 4.0D (formely OSF/1) on AlphaServer, the cc option -std1
  is necessary to get gzprintf working correctly. This is done by configure.

- zlib doesn't work on HP-UX 9.05 with some versions of /bin/cc. It works
  with other compilers. Use "make test" to check your compiler.

- gzdopen is not supported on RISCOS, BEOS and by some Mac compilers.

- For Turbo C the small model is supported only with reduced performance to
  avoid any far allocation; it was tested with -DMAX_WBITS=11 -DMAX_MEM_LEVEL=3

- For PalmOs, see http://www.cs.uit.no/~perm/PASTA/pilot/software.html
  Per Harald Myrvang <perm@stud.cs.uit.no>


Acknowledgments:

  The deflate format used by zlib was defined by Phil Katz. The deflate
  and zlib specifications were written by L. Peter Deutsch. Thanks to all the
  people who reported problems and suggested various improvements in zlib;
  they are too numerous to cite here.

Copyright notice:

 (C) 1995-2002 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu

If you use the zlib library in a product, we would appreciate *not*
receiving lengthy legal documents to sign. The sources are provided
for free but without warranty of any kind.  The library has been
entirely written by Jean-loup Gailly and Mark Adler; it does not
include third-party code.

If you redistribute modified sources, we would appreciate that you include
in the file ChangeLog history information documenting your changes.
