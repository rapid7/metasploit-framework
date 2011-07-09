Code and documentation are copyright 2006-2008 Henning Norén

Parts of pdfcrack.c and md5.c is derived/copied/inspired from
xpdf/poppler and are copyright 1995-2006 Glyph & Cog, LLC.

The PDF data structures, operators, and specification are
copyright 1985-2006 Adobe Systems Inc.


Project page: http://sourceforge.net/projects/pdfcrack/


pdfcrack is a simple tool for recovering passwords from pdf-documents.
It should be able to handle all pdfs that uses the standard security handler
but the pdf-parsing routines are a bit of a quick hack so you might stumble
across some pdfs where the parser needs to be fixed to handle.

Type 'make' (or 'gmake' if you have BSD-make as default) to build the program.
You will need to have GNU Make and a recent version of GCC installed but there
are no external dependencies on libraries.
You will have to add the -march-switch in the CFLAGS-option in Makefile
for best optimization on your platform. Look into the GCC-manual
(http://gcc.gnu.org/onlinedocs/) if you are unsure.

The program is distributed under GPL version 2 (or later).

Features available in this release (check TODO for features that might come):
* Both owner- and user-passwords with the Standard Security Handler, rev 2 & 3.
* Search by wordlist
* Search by bruteforcing with specific charset
* Optimized search for owner-password when user-password is known (or empty)
* Extremely simple permutations of passwords (makes first letter uppercase)

- currently only useful for bruteforcing with charsets:
* Auto-save when interrupted (Ctrl-C or send SIGINT to the process)
* Loading saved state

- currently only for bruteforcing with charsets:
* Minimum length of password to start at
* Maximum length of password to try


Sort your wordlist by length for best performance and consider that almost
all passwords in PDFs are in iso latin 1 so use the correct character encoding
in your terminal and/or wordlist when using special characters.

This tool can not decrypt a Password Protected PDF.
Look up the pdftk toolkit which can do that, when you know the password.
