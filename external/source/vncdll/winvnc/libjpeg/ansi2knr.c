/* ansi2knr.c */
/* Convert ANSI C function definitions to K&R ("traditional C") syntax */

/*
ansi2knr is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY.  No author or distributor accepts responsibility to anyone for the
consequences of using it or for whether it serves any particular purpose or
works at all, unless he says so in writing.  Refer to the GNU General Public
License (the "GPL") for full details.

Everyone is granted permission to copy, modify and redistribute ansi2knr,
but only under the conditions described in the GPL.  A copy of this license
is supposed to have been given to you along with ansi2knr so you can know
your rights and responsibilities.  It should be in a file named COPYLEFT.
[In the IJG distribution, the GPL appears below, not in a separate file.]
Among other things, the copyright notice and this notice must be preserved
on all copies.

We explicitly state here what we believe is already implied by the GPL: if
the ansi2knr program is distributed as a separate set of sources and a
separate executable file which are aggregated on a storage medium together
with another program, this in itself does not bring the other program under
the GPL, nor does the mere fact that such a program or the procedures for
constructing it invoke the ansi2knr executable bring any other part of the
program under the GPL.
*/

/*
---------- Here is the GNU GPL file COPYLEFT, referred to above ----------
----- These terms do NOT apply to the JPEG software itself; see README ------

		    GHOSTSCRIPT GENERAL PUBLIC LICENSE
		    (Clarified 11 Feb 1988)

 Copyright (C) 1988 Richard M. Stallman
 Everyone is permitted to copy and distribute verbatim copies of this
 license, but changing it is not allowed.  You can also use this wording
 to make the terms for other programs.

  The license agreements of most software companies keep you at the
mercy of those companies.  By contrast, our general public license is
intended to give everyone the right to share Ghostscript.  To make sure
that you get the rights we want you to have, we need to make
restrictions that forbid anyone to deny you these rights or to ask you
to surrender the rights.  Hence this license agreement.

  Specifically, we want to make sure that you have the right to give
away copies of Ghostscript, that you receive source code or else can get
it if you want it, that you can change Ghostscript or use pieces of it
in new free programs, and that you know you can do these things.

  To make sure that everyone has such rights, we have to forbid you to
deprive anyone else of these rights.  For example, if you distribute
copies of Ghostscript, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must tell them their rights.

  Also, for our own protection, we must make certain that everyone finds
out that there is no warranty for Ghostscript.  If Ghostscript is
modified by someone else and passed on, we want its recipients to know
that what they have is not what we distributed, so that any problems
introduced by others will not reflect on our reputation.

  Therefore we (Richard M. Stallman and the Free Software Foundation,
Inc.) make the following terms which say what you must do to be allowed
to distribute or change Ghostscript.


			COPYING POLICIES

  1. You may copy and distribute verbatim copies of Ghostscript source
code as you receive it, in any medium, provided that you conspicuously
and appropriately publish on each copy a valid copyright and license
notice "Copyright (C) 1989 Aladdin Enterprises.  All rights reserved.
Distributed by Free Software Foundation, Inc." (or with whatever year is
appropriate); keep intact the notices on all files that refer to this
License Agreement and to the absence of any warranty; and give any other
recipients of the Ghostscript program a copy of this License Agreement
along with the program.  You may charge a distribution fee for the
physical act of transferring a copy.

  2. You may modify your copy or copies of Ghostscript or any portion of
it, and copy and distribute such modifications under the terms of
Paragraph 1 above, provided that you also do the following:

    a) cause the modified files to carry prominent notices stating
    that you changed the files and the date of any change; and

    b) cause the whole of any work that you distribute or publish,
    that in whole or in part contains or is a derivative of Ghostscript
    or any part thereof, to be licensed at no charge to all third
    parties on terms identical to those contained in this License
    Agreement (except that you may choose to grant more extensive
    warranty protection to some or all third parties, at your option).

    c) You may charge a distribution fee for the physical act of
    transferring a copy, and you may at your option offer warranty
    protection in exchange for a fee.

Mere aggregation of another unrelated program with this program (or its
derivative) on a volume of a storage or distribution medium does not bring
the other program under the scope of these terms.

  3. You may copy and distribute Ghostscript (or a portion or derivative
of it, under Paragraph 2) in object code or executable form under the
terms of Paragraphs 1 and 2 above provided that you also do one of the
following:

    a) accompany it with the complete corresponding machine-readable
    source code, which must be distributed under the terms of
    Paragraphs 1 and 2 above; or,

    b) accompany it with a written offer, valid for at least three
    years, to give any third party free (except for a nominal
    shipping charge) a complete machine-readable copy of the
    corresponding source code, to be distributed under the terms of
    Paragraphs 1 and 2 above; or,

    c) accompany it with the information you received as to where the
    corresponding source code may be obtained.  (This alternative is
    allowed only for noncommercial distribution and only if you
    received the program in object code or executable form alone.)

For an executable file, complete source code means all the source code for
all modules it contains; but, as a special exception, it need not include
source code for modules which are standard libraries that accompany the
operating system on which the executable file runs.

  4. You may not copy, sublicense, distribute or transfer Ghostscript
except as expressly provided under this License Agreement.  Any attempt
otherwise to copy, sublicense, distribute or transfer Ghostscript is
void and your rights to use the program under this License agreement
shall be automatically terminated.  However, parties who have received
computer software programs from you with this License Agreement will not
have their licenses terminated so long as such parties remain in full
compliance.

  5. If you wish to incorporate parts of Ghostscript into other free
programs whose distribution conditions are different, write to the Free
Software Foundation at 675 Mass Ave, Cambridge, MA 02139.  We have not
yet worked out a simple rule that can be stated here, but we will often
permit this.  We will be guided by the two goals of preserving the free
status of all derivatives of our free software and of promoting the
sharing and reuse of software.

Your comments and suggestions about our licensing policies and our
software are welcome!  Please contact the Free Software Foundation,
Inc., 675 Mass Ave, Cambridge, MA 02139, or call (617) 876-3296.

		       NO WARRANTY

  BECAUSE GHOSTSCRIPT IS LICENSED FREE OF CHARGE, WE PROVIDE ABSOLUTELY
NO WARRANTY, TO THE EXTENT PERMITTED BY APPLICABLE STATE LAW.  EXCEPT
WHEN OTHERWISE STATED IN WRITING, FREE SOFTWARE FOUNDATION, INC, RICHARD
M. STALLMAN, ALADDIN ENTERPRISES, L. PETER DEUTSCH, AND/OR OTHER PARTIES
PROVIDE GHOSTSCRIPT "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF GHOSTSCRIPT IS WITH
YOU.  SHOULD GHOSTSCRIPT PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR OR CORRECTION.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW WILL RICHARD M.
STALLMAN, THE FREE SOFTWARE FOUNDATION, INC., L. PETER DEUTSCH, ALADDIN
ENTERPRISES, AND/OR ANY OTHER PARTY WHO MAY MODIFY AND REDISTRIBUTE
GHOSTSCRIPT AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING
ANY LOST PROFITS, LOST MONIES, OR OTHER SPECIAL, INCIDENTAL OR
CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
(INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED
INACCURATE OR LOSSES SUSTAINED BY THIRD PARTIES OR A FAILURE OF THE
PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS) GHOSTSCRIPT, EVEN IF YOU
HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM
BY ANY OTHER PARTY.

-------------------- End of file COPYLEFT ------------------------------
*/

/*
 * Usage:
	ansi2knr input_file [output_file]
 * If no output_file is supplied, output goes to stdout.
 * There are no error messages.
 *
 * ansi2knr recognizes function definitions by seeing a non-keyword
 * identifier at the left margin, followed by a left parenthesis,
 * with a right parenthesis as the last character on the line,
 * and with a left brace as the first token on the following line
 * (ignoring possible intervening comments).
 * It will recognize a multi-line header provided that no intervening
 * line ends with a left or right brace or a semicolon.
 * These algorithms ignore whitespace and comments, except that
 * the function name must be the first thing on the line.
 * The following constructs will confuse it:
 *	- Any other construct that starts at the left margin and
 *	    follows the above syntax (such as a macro or function call).
 *	- Some macros that tinker with the syntax of the function header.
 */

/*
 * The original and principal author of ansi2knr is L. Peter Deutsch
 * <ghost@aladdin.com>.  Other authors are noted in the change history
 * that follows (in reverse chronological order):
	lpd 96-01-21 added code to cope with not HAVE_CONFIG_H and with
		compilers that don't understand void, as suggested by
		Tom Lane
	lpd 96-01-15 changed to require that the first non-comment token
		on the line following a function header be a left brace,
		to reduce sensitivity to macros, as suggested by Tom Lane
		<tgl@sss.pgh.pa.us>
	lpd 95-06-22 removed #ifndefs whose sole purpose was to define
		undefined preprocessor symbols as 0; changed all #ifdefs
		for configuration symbols to #ifs
	lpd 95-04-05 changed copyright notice to make it clear that
		including ansi2knr in a program does not bring the entire
		program under the GPL
	lpd 94-12-18 added conditionals for systems where ctype macros
		don't handle 8-bit characters properly, suggested by
		Francois Pinard <pinard@iro.umontreal.ca>;
		removed --varargs switch (this is now the default)
	lpd 94-10-10 removed CONFIG_BROKETS conditional
	lpd 94-07-16 added some conditionals to help GNU `configure',
		suggested by Francois Pinard <pinard@iro.umontreal.ca>;
		properly erase prototype args in function parameters,
		contributed by Jim Avera <jima@netcom.com>;
		correct error in writeblanks (it shouldn't erase EOLs)
	lpd 89-xx-xx original version
 */

/* Most of the conditionals here are to make ansi2knr work with */
/* or without the GNU configure machinery. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>

#if HAVE_CONFIG_H

/*
   For properly autoconfiguring ansi2knr, use AC_CONFIG_HEADER(config.h).
   This will define HAVE_CONFIG_H and so, activate the following lines.
 */

# if STDC_HEADERS || HAVE_STRING_H
#  include <string.h>
# else
#  include <strings.h>
# endif

#else /* not HAVE_CONFIG_H */

/* Otherwise do it the hard way */

# ifdef BSD
#  include <strings.h>
# else
#  ifdef VMS
    extern int strlen(), strncmp();
#  else
#   include <string.h>
#  endif
# endif

#endif /* not HAVE_CONFIG_H */

#if STDC_HEADERS
# include <stdlib.h>
#else
/*
   malloc and free should be declared in stdlib.h,
   but if you've got a K&R compiler, they probably aren't.
 */
# ifdef MSDOS
#  include <malloc.h>
# else
#  ifdef VMS
     extern char *malloc();
     extern void free();
#  else
     extern char *malloc();
     extern int free();
#  endif
# endif

#endif

/*
 * The ctype macros don't always handle 8-bit characters correctly.
 * Compensate for this here.
 */
#ifdef isascii
#  undef HAVE_ISASCII		/* just in case */
#  define HAVE_ISASCII 1
#else
#endif
#if STDC_HEADERS || !HAVE_ISASCII
#  define is_ascii(c) 1
#else
#  define is_ascii(c) isascii(c)
#endif

#define is_space(c) (is_ascii(c) && isspace(c))
#define is_alpha(c) (is_ascii(c) && isalpha(c))
#define is_alnum(c) (is_ascii(c) && isalnum(c))

/* Scanning macros */
#define isidchar(ch) (is_alnum(ch) || (ch) == '_')
#define isidfirstchar(ch) (is_alpha(ch) || (ch) == '_')

/* Forward references */
char *skipspace();
int writeblanks();
int test1();
int convert1();

/* The main program */
int
main(argc, argv)
    int argc;
    char *argv[];
{	FILE *in, *out;
#define bufsize 5000			/* arbitrary size */
	char *buf;
	char *line;
	char *more;
	/*
	 * In previous versions, ansi2knr recognized a --varargs switch.
	 * If this switch was supplied, ansi2knr would attempt to convert
	 * a ... argument to va_alist and va_dcl; if this switch was not
	 * supplied, ansi2knr would simply drop any such arguments.
	 * Now, ansi2knr always does this conversion, and we only
	 * check for this switch for backward compatibility.
	 */
	int convert_varargs = 1;

	if ( argc > 1 && argv[1][0] == '-' )
	  {	if ( !strcmp(argv[1], "--varargs") )
		  {	convert_varargs = 1;
			argc--;
			argv++;
		  }
		else
		  {	fprintf(stderr, "Unrecognized switch: %s\n", argv[1]);
			exit(1);
		  }
	  }
	switch ( argc )
	   {
	default:
		printf("Usage: ansi2knr input_file [output_file]\n");
		exit(0);
	case 2:
		out = stdout;
		break;
	case 3:
		out = fopen(argv[2], "w");
		if ( out == NULL )
		   {	fprintf(stderr, "Cannot open output file %s\n", argv[2]);
			exit(1);
		   }
	   }
	in = fopen(argv[1], "r");
	if ( in == NULL )
	   {	fprintf(stderr, "Cannot open input file %s\n", argv[1]);
		exit(1);
	   }
	fprintf(out, "#line 1 \"%s\"\n", argv[1]);
	buf = malloc(bufsize);
	line = buf;
	while ( fgets(line, (unsigned)(buf + bufsize - line), in) != NULL )
	   {
test:		line += strlen(line);
		switch ( test1(buf) )
		   {
		case 2:			/* a function header */
			convert1(buf, out, 1, convert_varargs);
			break;
		case 1:			/* a function */
			/* Check for a { at the start of the next line. */
			more = ++line;
f:			if ( line >= buf + (bufsize - 1) ) /* overflow check */
			  goto wl;
			if ( fgets(line, (unsigned)(buf + bufsize - line), in) == NULL )
			  goto wl;
			switch ( *skipspace(more, 1) )
			  {
			  case '{':
			    /* Definitely a function header. */
			    convert1(buf, out, 0, convert_varargs);
			    fputs(more, out);
			    break;
			  case 0:
			    /* The next line was blank or a comment: */
			    /* keep scanning for a non-comment. */
			    line += strlen(line);
			    goto f;
			  default:
			    /* buf isn't a function header, but */
			    /* more might be. */
			    fputs(buf, out);
			    strcpy(buf, more);
			    line = buf;
			    goto test;
			  }
			break;
		case -1:		/* maybe the start of a function */
			if ( line != buf + (bufsize - 1) ) /* overflow check */
			  continue;
			/* falls through */
		default:		/* not a function */
wl:			fputs(buf, out);
			break;
		   }
		line = buf;
	   }
	if ( line != buf )
	  fputs(buf, out);
	free(buf);
	fclose(out);
	fclose(in);
	return 0;
}

/* Skip over space and comments, in either direction. */
char *
skipspace(p, dir)
    register char *p;
    register int dir;			/* 1 for forward, -1 for backward */
{	for ( ; ; )
	   {	while ( is_space(*p) )
		  p += dir;
		if ( !(*p == '/' && p[dir] == '*') )
		  break;
		p += dir;  p += dir;
		while ( !(*p == '*' && p[dir] == '/') )
		   {	if ( *p == 0 )
			  return p;	/* multi-line comment?? */
			p += dir;
		   }
		p += dir;  p += dir;
	   }
	return p;
}

/*
 * Write blanks over part of a string.
 * Don't overwrite end-of-line characters.
 */
int
writeblanks(start, end)
    char *start;
    char *end;
{	char *p;
	for ( p = start; p < end; p++ )
	  if ( *p != '\r' && *p != '\n' )
	    *p = ' ';
	return 0;
}

/*
 * Test whether the string in buf is a function definition.
 * The string may contain and/or end with a newline.
 * Return as follows:
 *	0 - definitely not a function definition;
 *	1 - definitely a function definition;
 *	2 - definitely a function prototype (NOT USED);
 *	-1 - may be the beginning of a function definition,
 *		append another line and look again.
 * The reason we don't attempt to convert function prototypes is that
 * Ghostscript's declaration-generating macros look too much like
 * prototypes, and confuse the algorithms.
 */
int
test1(buf)
    char *buf;
{	register char *p = buf;
	char *bend;
	char *endfn;
	int contin;

	if ( !isidfirstchar(*p) )
	  return 0;		/* no name at left margin */
	bend = skipspace(buf + strlen(buf) - 1, -1);
	switch ( *bend )
	   {
	   case ';': contin = 0 /*2*/; break;
	   case ')': contin = 1; break;
	   case '{': return 0;		/* not a function */
	   case '}': return 0;		/* not a function */
	   default: contin = -1;
	   }
	while ( isidchar(*p) )
	  p++;
	endfn = p;
	p = skipspace(p, 1);
	if ( *p++ != '(' )
	  return 0;		/* not a function */
	p = skipspace(p, 1);
	if ( *p == ')' )
	  return 0;		/* no parameters */
	/* Check that the apparent function name isn't a keyword. */
	/* We only need to check for keywords that could be followed */
	/* by a left parenthesis (which, unfortunately, is most of them). */
	   {	static char *words[] =
		   {	"asm", "auto", "case", "char", "const", "double",
			"extern", "float", "for", "if", "int", "long",
			"register", "return", "short", "signed", "sizeof",
			"static", "switch", "typedef", "unsigned",
			"void", "volatile", "while", 0
		   };
		char **key = words;
		char *kp;
		int len = endfn - buf;

		while ( (kp = *key) != 0 )
		   {	if ( strlen(kp) == len && !strncmp(kp, buf, len) )
			  return 0;	/* name is a keyword */
			key++;
		   }
	   }
	return contin;
}

/* Convert a recognized function definition or header to K&R syntax. */
int
convert1(buf, out, header, convert_varargs)
    char *buf;
    FILE *out;
    int header;			/* Boolean */
    int convert_varargs;	/* Boolean */
{	char *endfn;
	register char *p;
	char **breaks;
	unsigned num_breaks = 2;	/* for testing */
	char **btop;
	char **bp;
	char **ap;
	char *vararg = 0;

	/* Pre-ANSI implementations don't agree on whether strchr */
	/* is called strchr or index, so we open-code it here. */
	for ( endfn = buf; *(endfn++) != '('; )
	  ;
top:	p = endfn;
	breaks = (char **)malloc(sizeof(char *) * num_breaks * 2);
	if ( breaks == 0 )
	   {	/* Couldn't allocate break table, give up */
		fprintf(stderr, "Unable to allocate break table!\n");
		fputs(buf, out);
		return -1;
	   }
	btop = breaks + num_breaks * 2 - 2;
	bp = breaks;
	/* Parse the argument list */
	do
	   {	int level = 0;
		char *lp = NULL;
		char *rp;
		char *end = NULL;

		if ( bp >= btop )
		   {	/* Filled up break table. */
			/* Allocate a bigger one and start over. */
			free((char *)breaks);
			num_breaks <<= 1;
			goto top;
		   }
		*bp++ = p;
		/* Find the end of the argument */
		for ( ; end == NULL; p++ )
		   {	switch(*p)
			   {
			   case ',':
				if ( !level ) end = p;
				break;
			   case '(':
				if ( !level ) lp = p;
				level++;
				break;
			   case ')':
				if ( --level < 0 ) end = p;
				else rp = p;
				break;
			   case '/':
				p = skipspace(p, 1) - 1;
				break;
			   default:
				;
			   }
		   }
		/* Erase any embedded prototype parameters. */
		if ( lp )
		  writeblanks(lp + 1, rp);
		p--;			/* back up over terminator */
		/* Find the name being declared. */
		/* This is complicated because of procedure and */
		/* array modifiers. */
		for ( ; ; )
		   {	p = skipspace(p - 1, -1);
			switch ( *p )
			   {
			   case ']':	/* skip array dimension(s) */
			   case ')':	/* skip procedure args OR name */
			   {	int level = 1;
				while ( level )
				 switch ( *--p )
				   {
				   case ']': case ')': level++; break;
				   case '[': case '(': level--; break;
				   case '/': p = skipspace(p, -1) + 1; break;
				   default: ;
				   }
			   }
				if ( *p == '(' && *skipspace(p + 1, 1) == '*' )
				   {	/* We found the name being declared */
					while ( !isidfirstchar(*p) )
					  p = skipspace(p, 1) + 1;
					goto found;
				   }
				break;
			   default:
				goto found;
			   }
		   }
found:		if ( *p == '.' && p[-1] == '.' && p[-2] == '.' )
		  {	if ( convert_varargs )
			  {	*bp++ = "va_alist";
				vararg = p-2;
			  }
			else
			  {	p++;
				if ( bp == breaks + 1 )	/* sole argument */
				  writeblanks(breaks[0], p);
				else
				  writeblanks(bp[-1] - 1, p);
				bp--;
			  }
		   }
		else
		   {	while ( isidchar(*p) ) p--;
			*bp++ = p+1;
		   }
		p = end;
	   }
	while ( *p++ == ',' );
	*bp = p;
	/* Make a special check for 'void' arglist */
	if ( bp == breaks+2 )
	   {	p = skipspace(breaks[0], 1);
		if ( !strncmp(p, "void", 4) )
		   {	p = skipspace(p+4, 1);
			if ( p == breaks[2] - 1 )
			   {	bp = breaks;	/* yup, pretend arglist is empty */
				writeblanks(breaks[0], p + 1);
			   }
		   }
	   }
	/* Put out the function name and left parenthesis. */
	p = buf;
	while ( p != endfn ) putc(*p, out), p++;
	/* Put out the declaration. */
	if ( header )
	  {	fputs(");", out);
		for ( p = breaks[0]; *p; p++ )
		  if ( *p == '\r' || *p == '\n' )
		    putc(*p, out);
	  }
	else
	  {	for ( ap = breaks+1; ap < bp; ap += 2 )
		  {	p = *ap;
			while ( isidchar(*p) )
			  putc(*p, out), p++;
			if ( ap < bp - 1 )
			  fputs(", ", out);
		  }
		fputs(")  ", out);
		/* Put out the argument declarations */
		for ( ap = breaks+2; ap <= bp; ap += 2 )
		  (*ap)[-1] = ';';
		if ( vararg != 0 )
		  {	*vararg = 0;
			fputs(breaks[0], out);		/* any prior args */
			fputs("va_dcl", out);		/* the final arg */
			fputs(bp[0], out);
		  }
		else
		  fputs(breaks[0], out);
	  }
	free((char *)breaks);
	return 0;
}
