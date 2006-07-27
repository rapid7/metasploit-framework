/* readline.c -- GNU Readline module
   Copyright (C) 1997-2001  Shugo Maeda */

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifdef HAVE_READLINE_READLINE_H
#include <readline/readline.h>
#endif
#ifdef HAVE_READLINE_HISTORY_H
#include <readline/history.h>
#endif
#ifdef HAVE_EDITLINE_READLINE_H
#include <editline/readline.h>
#endif

#include "ruby.h"
#include "rubyio.h"
#include "rubysig.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static VALUE mReadline;

#define TOLOWER(c) (isupper(c) ? tolower(c) : c)

#define COMPLETION_PROC "completion_proc"
#define COMPLETION_CASE_FOLD "completion_case_fold"
static ID completion_proc, completion_case_fold;

#ifndef HAVE_RL_FILENAME_COMPLETION_FUNCTION
# define rl_filename_completion_function filename_completion_function
# define rl_username_completion_function username_completion_function
# define rl_completion_matches completion_matches
#endif

static int readline_event(void);
static char **readline_attempted_completion_function(const char *text,
                                                     int start, int end);

static int
readline_event()
{
    CHECK_INTS;
    rb_thread_schedule();
    return 0;
}

static VALUE
readline_readline(argc, argv, self)
    int argc;
    VALUE *argv;
    VALUE self;
{
    VALUE tmp, add_hist, result, alt_inp, alt_out;
    char *prompt = NULL;
    char *buff;
    int status;
    OpenFile *ofp, *ifp;

    rb_secure(4);
    if (rb_scan_args(argc, argv, "02", &tmp, &add_hist) > 0) {
	SafeStringValue(tmp);
	prompt = RSTRING(tmp)->ptr;
    }

	alt_inp = rb_gv_get("$READLINE_STDIN");
	alt_out = rb_gv_get("$READLINE_STDOUT");
	
	if (alt_inp == Qnil)	
	    if (!isatty(0) && errno == EBADF) rb_raise(rb_eIOError, "stdin closed");

	if(alt_out == Qnil) {
	    Check_Type(rb_stdout, T_FILE);
	    GetOpenFile(rb_stdout, ofp);
	    rl_outstream = GetWriteFile(ofp);
	} else {
	    Check_Type(alt_out, T_FILE);
	    GetOpenFile(alt_out, ofp);
	    rl_outstream = GetWriteFile(ofp);		
	}
	
	if(alt_inp == Qnil){
		Check_Type(rb_stdin, T_FILE);
    	GetOpenFile(rb_stdin, ifp);
    	rl_instream = GetReadFile(ifp);
	} else {
		Check_Type(alt_inp, T_FILE);
    	GetOpenFile(alt_inp, ifp);
    	rl_instream = GetReadFile(ifp);		
	}
	
    buff = (char*)rb_protect((VALUE(*)_((VALUE)))readline, (VALUE)prompt,
                              &status);
    if (status) {
#if defined HAVE_RL_CLEANUP_AFTER_SIGNAL
        /* restore terminal mode and signal handler*/
        rl_cleanup_after_signal();
#elif defined HAVE_RL_DEPREP_TERM_FUNCTION
        /* restore terminal mode */
        (*rl_deprep_term_function)();
#else
        rl_deprep_terminal();
#endif
        rb_jump_tag(status);
    }

    if (RTEST(add_hist) && buff) {
	add_history(buff);
    }
    if (buff)
	result = rb_tainted_str_new2(buff);
    else
	result = Qnil;
    if (buff) free(buff);
    return result;
}

static VALUE
readline_s_set_completion_proc(self, proc)
    VALUE self;
    VALUE proc;
{
    rb_secure(4);
    if (!rb_respond_to(proc, rb_intern("call")))
	rb_raise(rb_eArgError, "argument must respond to `call'");
    return rb_ivar_set(mReadline, completion_proc, proc);
}

static VALUE
readline_s_get_completion_proc(self)
    VALUE self;
{
    rb_secure(4);
    return rb_attr_get(mReadline, completion_proc);
}

static VALUE
readline_s_set_completion_case_fold(self, val)
    VALUE self;
    VALUE val;
{
    rb_secure(4);
    return rb_ivar_set(mReadline, completion_case_fold, val);
}

static VALUE
readline_s_get_completion_case_fold(self)
    VALUE self;
{
    rb_secure(4);
    return rb_attr_get(mReadline, completion_case_fold);
}

static char **
readline_attempted_completion_function(text, start, end)
    const char *text;
    int start;
    int end;
{
    VALUE proc, ary, temp;
    char **result;
    int case_fold;
    int i, matches;

    proc = rb_attr_get(mReadline, completion_proc);
    if (NIL_P(proc))
	return NULL;
#ifdef HAVE_RL_ATTEMPTED_COMPLETION_OVER
    rl_attempted_completion_over = 1;
#endif
    case_fold = RTEST(rb_attr_get(mReadline, completion_case_fold));
    ary = rb_funcall(proc, rb_intern("call"), 1, rb_tainted_str_new2(text));
    if (TYPE(ary) != T_ARRAY)
	ary = rb_Array(ary);
    matches = RARRAY(ary)->len;
    if (matches == 0)
	return NULL;
    result = ALLOC_N(char *, matches + 2);
    for (i = 0; i < matches; i++) {
	temp = rb_obj_as_string(RARRAY(ary)->ptr[i]);
	result[i + 1] = ALLOC_N(char, RSTRING(temp)->len + 1);
	strcpy(result[i + 1], RSTRING(temp)->ptr);
    }
    result[matches + 1] = NULL;

    if (matches == 1) {
        result[0] = strdup(result[1]);
    }
    else {
	register int i = 1;
	int low = 100000;

	while (i < matches) {
	    register int c1, c2, si;

	    if (case_fold) {
		for (si = 0;
		     (c1 = TOLOWER(result[i][si])) &&
			 (c2 = TOLOWER(result[i + 1][si]));
		     si++)
		    if (c1 != c2) break;
	    } else {
		for (si = 0;
		     (c1 = result[i][si]) &&
			 (c2 = result[i + 1][si]);
		     si++)
		    if (c1 != c2) break;
	    }

	    if (low > si) low = si;
	    i++;
	}
	result[0] = ALLOC_N(char, low + 1);
	strncpy(result[0], result[1], low);
	result[0][low] = '\0';
    }

    return result;
}

static VALUE
readline_s_vi_editing_mode(self)
    VALUE self;
{
#ifdef HAVE_RL_VI_EDITING_MODE
    rb_secure(4);
    rl_vi_editing_mode(1,0);
    return Qnil;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_VI_EDITING_MODE */
}

static VALUE
readline_s_emacs_editing_mode(self)
    VALUE self;
{
#ifdef HAVE_RL_EMACS_EDITING_MODE
    rb_secure(4);
    rl_emacs_editing_mode(1,0);
    return Qnil;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_EMACS_EDITING_MODE */
}

static VALUE
readline_s_set_completion_append_character(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_COMPLETION_APPEND_CHARACTER
    rb_secure(4);
    if (NIL_P(str)) {
	rl_completion_append_character = '\0';
    }
    else {
	SafeStringValue(str);
	if (RSTRING(str)->len == 0) {
	    rl_completion_append_character = '\0';
	} else {
	    rl_completion_append_character = RSTRING(str)->ptr[0];
	}
    }
    return self;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_COMPLETION_APPEND_CHARACTER */
}

static VALUE
readline_s_get_completion_append_character(self)
    VALUE self;
{
#ifdef HAVE_RL_COMPLETION_APPEND_CHARACTER
    VALUE str;

    rb_secure(4);
    if (rl_completion_append_character == '\0')
	return Qnil;

    str = rb_str_new("", 1);
    RSTRING(str)->ptr[0] = rl_completion_append_character;
    return str;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_COMPLETION_APPEND_CHARACTER */
}

static VALUE
readline_s_set_basic_word_break_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_BASIC_WORD_BREAK_CHARACTERS
    static char *basic_word_break_characters = NULL;

    rb_secure(4);
    SafeStringValue(str);
    if (basic_word_break_characters == NULL) {
	basic_word_break_characters =
	    ALLOC_N(char, RSTRING(str)->len + 1);
    }
    else {
	REALLOC_N(basic_word_break_characters, char, RSTRING(str)->len + 1);
    }
    strncpy(basic_word_break_characters,
	    RSTRING(str)->ptr, RSTRING(str)->len);
    basic_word_break_characters[RSTRING(str)->len] = '\0';
    rl_basic_word_break_characters = basic_word_break_characters;
    return self;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_BASIC_WORD_BREAK_CHARACTERS */
}

static VALUE
readline_s_get_basic_word_break_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_BASIC_WORD_BREAK_CHARACTERS
    rb_secure(4);
    if (rl_basic_word_break_characters == NULL)
	return Qnil;
    return rb_tainted_str_new2(rl_basic_word_break_characters);
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_BASIC_WORD_BREAK_CHARACTERS */
}

static VALUE
readline_s_set_completer_word_break_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_COMPLETER_WORD_BREAK_CHARACTERS
    static char *completer_word_break_characters = NULL;

    rb_secure(4);
    SafeStringValue(str);
    if (completer_word_break_characters == NULL) {
	completer_word_break_characters =
	    ALLOC_N(char, RSTRING(str)->len + 1);
    }
    else {
	REALLOC_N(completer_word_break_characters, char, RSTRING(str)->len + 1);
    }
    strncpy(completer_word_break_characters,
	    RSTRING(str)->ptr, RSTRING(str)->len);
    completer_word_break_characters[RSTRING(str)->len] = '\0';
    rl_completer_word_break_characters = completer_word_break_characters;
    return self;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_COMPLETER_WORD_BREAK_CHARACTERS */
}

static VALUE
readline_s_get_completer_word_break_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_COMPLETER_WORD_BREAK_CHARACTERS
    rb_secure(4);
    if (rl_completer_word_break_characters == NULL)
	return Qnil;
    return rb_tainted_str_new2(rl_completer_word_break_characters);
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_COMPLETER_WORD_BREAK_CHARACTERS */
}

static VALUE
readline_s_set_basic_quote_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_BASIC_QUOTE_CHARACTERS
    static char *basic_quote_characters = NULL;

    rb_secure(4);
    SafeStringValue(str);
    if (basic_quote_characters == NULL) {
	basic_quote_characters =
	    ALLOC_N(char, RSTRING(str)->len + 1);
    }
    else {
	REALLOC_N(basic_quote_characters, char, RSTRING(str)->len + 1);
    }
    strncpy(basic_quote_characters,
	    RSTRING(str)->ptr, RSTRING(str)->len);
    basic_quote_characters[RSTRING(str)->len] = '\0';
    rl_basic_quote_characters = basic_quote_characters;

    return self;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_BASIC_QUOTE_CHARACTERS */
}

static VALUE
readline_s_get_basic_quote_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_BASIC_QUOTE_CHARACTERS
    rb_secure(4);
    if (rl_basic_quote_characters == NULL)
	return Qnil;
    return rb_tainted_str_new2(rl_basic_quote_characters);
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_BASIC_QUOTE_CHARACTERS */
}

static VALUE
readline_s_set_completer_quote_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_COMPLETER_QUOTE_CHARACTERS
    static char *completer_quote_characters = NULL;

    rb_secure(4);
    SafeStringValue(str);
    if (completer_quote_characters == NULL) {
	completer_quote_characters =
	    ALLOC_N(char, RSTRING(str)->len + 1);
    }
    else {
	REALLOC_N(completer_quote_characters, char, RSTRING(str)->len + 1);
    }
    strncpy(completer_quote_characters,
	    RSTRING(str)->ptr, RSTRING(str)->len);
    completer_quote_characters[RSTRING(str)->len] = '\0';
    rl_completer_quote_characters = completer_quote_characters;

    return self;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_COMPLETER_QUOTE_CHARACTERS */
}

static VALUE
readline_s_get_completer_quote_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_COMPLETER_QUOTE_CHARACTERS
    rb_secure(4);
    if (rl_completer_quote_characters == NULL)
	return Qnil;
    return rb_tainted_str_new2(rl_completer_quote_characters);
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_COMPLETER_QUOTE_CHARACTERS */
}

static VALUE
readline_s_set_filename_quote_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_FILENAME_QUOTE_CHARACTERS
    static char *filename_quote_characters = NULL;

    rb_secure(4);
    SafeStringValue(str);
    if (filename_quote_characters == NULL) {
	filename_quote_characters =
	    ALLOC_N(char, RSTRING(str)->len + 1);
    }
    else {
	REALLOC_N(filename_quote_characters, char, RSTRING(str)->len + 1);
    }
    strncpy(filename_quote_characters,
	    RSTRING(str)->ptr, RSTRING(str)->len);
    filename_quote_characters[RSTRING(str)->len] = '\0';
    rl_filename_quote_characters = filename_quote_characters;

    return self;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_FILENAME_QUOTE_CHARACTERS */
}

static VALUE
readline_s_get_filename_quote_characters(self, str)
    VALUE self, str;
{
#ifdef HAVE_RL_FILENAME_QUOTE_CHARACTERS
    rb_secure(4);
    if (rl_filename_quote_characters == NULL)
	return Qnil;
    return rb_tainted_str_new2(rl_filename_quote_characters);
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif /* HAVE_RL_FILENAME_QUOTE_CHARACTERS */
}

static VALUE
hist_to_s(self)
    VALUE self;
{
    return rb_str_new2("HISTORY");
}

static VALUE
hist_get(self, index)
    VALUE self;
    VALUE index;
{
    HIST_ENTRY *entry;
    int i;

    rb_secure(4);
    i = NUM2INT(index);
    if (i < 0) {
        i += history_length;
    }
    entry = history_get(history_base + i);
    if (entry == NULL) {
	rb_raise(rb_eIndexError, "invalid index");
    }
    return rb_tainted_str_new2(entry->line);
}

static VALUE
hist_set(self, index, str)
    VALUE self;
    VALUE index;
    VALUE str;
{
#ifdef HAVE_REPLACE_HISTORY_ENTRY
    HIST_ENTRY *entry;
    int i;

    rb_secure(4);
    i = NUM2INT(index);
    SafeStringValue(str);
    if (i < 0) {
        i += history_length;
    }
    entry = replace_history_entry(i, RSTRING(str)->ptr, NULL);
    if (entry == NULL) {
	rb_raise(rb_eIndexError, "invalid index");
    }
    return str;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif
}

static VALUE
hist_push(self, str)
    VALUE self;
    VALUE str;
{
    rb_secure(4);
    SafeStringValue(str);
    add_history(RSTRING(str)->ptr);
    return self;
}

static VALUE
hist_push_method(argc, argv, self)
    int argc;
    VALUE *argv;
    VALUE self;
{
    VALUE str;
    
    rb_secure(4);
    while (argc--) {
	str = *argv++;
	SafeStringValue(str);
	add_history(RSTRING(str)->ptr);
    }
    return self;
}

static VALUE
rb_remove_history(index)
    int index;
{
#ifdef HAVE_REMOVE_HISTORY
    HIST_ENTRY *entry;
    VALUE val;

    rb_secure(4);
    entry = remove_history(index);
    if (entry) {
        val = rb_tainted_str_new2(entry->line);
        free(entry->line);
        free(entry);
        return val;
    }
    return Qnil;
#else
    rb_notimplement();
    return Qnil; /* not reached */
#endif
}

static VALUE
hist_pop(self)
    VALUE self;
{
    rb_secure(4);
    if (history_length > 0) {
	return rb_remove_history(history_length - 1);
    } else {
	return Qnil;
    }
}

static VALUE
hist_shift(self)
    VALUE self;
{
    rb_secure(4);
    if (history_length > 0) {
	return rb_remove_history(0);
    } else {
	return Qnil;
    }
}

static VALUE
hist_each(self)
    VALUE self;
{
    HIST_ENTRY *entry;
    int i;

    rb_secure(4);
    for (i = 0; i < history_length; i++) {
        entry = history_get(history_base + i);
        if (entry == NULL)
            break;
	rb_yield(rb_tainted_str_new2(entry->line));
    }
    return self;
}

static VALUE
hist_length(self)
    VALUE self;
{
    rb_secure(4);
    return INT2NUM(history_length);
}

static VALUE
hist_empty_p(self)
    VALUE self;
{
    rb_secure(4);
    return history_length == 0 ? Qtrue : Qfalse;
}

static VALUE
hist_delete_at(self, index)
    VALUE self;
    VALUE index;
{
    int i;

    rb_secure(4);
    i = NUM2INT(index);
    if (i < 0)
        i += history_length;
    if (i < 0 || i > history_length - 1) {
	rb_raise(rb_eIndexError, "invalid index");
    }
    return rb_remove_history(i);
}

static VALUE
filename_completion_proc_call(self, str)
    VALUE self;
    VALUE str;
{
    VALUE result;
    char **matches;
    int i;

    matches = rl_completion_matches(StringValuePtr(str),
				    rl_filename_completion_function);
    if (matches) {
	result = rb_ary_new();
	for (i = 0; matches[i]; i++) {
	    rb_ary_push(result, rb_tainted_str_new2(matches[i]));
	    free(matches[i]);
	}
	free(matches);
	if (RARRAY(result)->len >= 2)
	    rb_ary_shift(result);
    }
    else {
	result = Qnil;
    }
    return result;
}

static VALUE
username_completion_proc_call(self, str)
    VALUE self;
    VALUE str;
{
    VALUE result;
    char **matches;
    int i;

    matches = rl_completion_matches(StringValuePtr(str),
				    rl_username_completion_function);
    if (matches) {
	result = rb_ary_new();
	for (i = 0; matches[i]; i++) {
	    rb_ary_push(result, rb_tainted_str_new2(matches[i]));
	    free(matches[i]);
	}
	free(matches);
	if (RARRAY(result)->len >= 2)
	    rb_ary_shift(result);
    }
    else {
	result = Qnil;
    }
    return result;
}

void
Init_readline()
{
    VALUE history, fcomp, ucomp;

    /* Allow conditional parsing of the ~/.inputrc file. */
    rl_readline_name = "Ruby";

    using_history();

    completion_proc = rb_intern(COMPLETION_PROC);
    completion_case_fold = rb_intern(COMPLETION_CASE_FOLD);

    mReadline = rb_define_module("Readline");
    rb_define_module_function(mReadline, "readline",
			      readline_readline, -1);
    rb_define_singleton_method(mReadline, "completion_proc=",
			       readline_s_set_completion_proc, 1);
    rb_define_singleton_method(mReadline, "completion_proc",
			       readline_s_get_completion_proc, 0);
    rb_define_singleton_method(mReadline, "completion_case_fold=",
			       readline_s_set_completion_case_fold, 1);
    rb_define_singleton_method(mReadline, "completion_case_fold",
			       readline_s_get_completion_case_fold, 0);
    rb_define_singleton_method(mReadline, "vi_editing_mode",
			       readline_s_vi_editing_mode, 0);
    rb_define_singleton_method(mReadline, "emacs_editing_mode",
			       readline_s_emacs_editing_mode, 0);
    rb_define_singleton_method(mReadline, "completion_append_character=",
			       readline_s_set_completion_append_character, 1);
    rb_define_singleton_method(mReadline, "completion_append_character",
			       readline_s_get_completion_append_character, 0);
    rb_define_singleton_method(mReadline, "basic_word_break_characters=",
			       readline_s_set_basic_word_break_characters, 1);
    rb_define_singleton_method(mReadline, "basic_word_break_characters",
			       readline_s_get_basic_word_break_characters, 0);
    rb_define_singleton_method(mReadline, "completer_word_break_characters=",
			       readline_s_set_completer_word_break_characters, 1);
    rb_define_singleton_method(mReadline, "completer_word_break_characters",
			       readline_s_get_completer_word_break_characters, 0);
    rb_define_singleton_method(mReadline, "basic_quote_characters=",
			       readline_s_set_basic_quote_characters, 1);
    rb_define_singleton_method(mReadline, "basic_quote_characters",
			       readline_s_get_basic_quote_characters, 0);
    rb_define_singleton_method(mReadline, "completer_quote_characters=",
			       readline_s_set_completer_quote_characters, 1);
    rb_define_singleton_method(mReadline, "completer_quote_characters",
			       readline_s_get_completer_quote_characters, 0);
    rb_define_singleton_method(mReadline, "filename_quote_characters=",
			       readline_s_set_filename_quote_characters, 1);
    rb_define_singleton_method(mReadline, "filename_quote_characters",
			       readline_s_get_filename_quote_characters, 0);

    history = rb_obj_alloc(rb_cObject);
    rb_extend_object(history, rb_mEnumerable);
    rb_define_singleton_method(history,"to_s", hist_to_s, 0);
    rb_define_singleton_method(history,"[]", hist_get, 1);
    rb_define_singleton_method(history,"[]=", hist_set, 2);
    rb_define_singleton_method(history,"<<", hist_push, 1);
    rb_define_singleton_method(history,"push", hist_push_method, -1);
    rb_define_singleton_method(history,"pop", hist_pop, 0);
    rb_define_singleton_method(history,"shift", hist_shift, 0);
    rb_define_singleton_method(history,"each", hist_each, 0);
    rb_define_singleton_method(history,"length", hist_length, 0);
    rb_define_singleton_method(history,"size", hist_length, 0);
    rb_define_singleton_method(history,"empty?", hist_empty_p, 0);
    rb_define_singleton_method(history,"delete_at", hist_delete_at, 1);
    rb_define_const(mReadline, "HISTORY", history);

    fcomp = rb_obj_alloc(rb_cObject);
    rb_define_singleton_method(fcomp, "call",
			       filename_completion_proc_call, 1);
    rb_define_const(mReadline, "FILENAME_COMPLETION_PROC", fcomp);

    ucomp = rb_obj_alloc(rb_cObject);
    rb_define_singleton_method(ucomp, "call",
			       username_completion_proc_call, 1);
    rb_define_const(mReadline, "USERNAME_COMPLETION_PROC", ucomp);
#if defined HAVE_RL_LIBRARY_VERSION
    rb_define_const(mReadline, "VERSION", rb_str_new2(rl_library_version));
#else
    rb_define_const(mReadline, "VERSION",
                    rb_str_new2("2.0 or before version"));
#endif

    rl_attempted_completion_function = readline_attempted_completion_function;
#ifdef HAVE_RL_EVENT_HOOK
    rl_event_hook = readline_event;
#endif
#ifdef HAVE_RL_CLEAR_SIGNALS
    rl_clear_signals();
#endif
}
