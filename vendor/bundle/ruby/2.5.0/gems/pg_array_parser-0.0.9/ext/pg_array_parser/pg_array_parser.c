#include <ruby.h>
#include <ruby/encoding.h>

/* Prototype */
VALUE read_array(int *index, char *string, int length, char *word, rb_encoding *enc);

VALUE parse_pg_array(VALUE self, VALUE pg_array_string) {

  /* convert to c-string, create a buffer of the same length, as that will be the worst case */
  char *c_pg_array_string = StringValueCStr(pg_array_string);
  int array_string_length = RSTRING_LEN(pg_array_string);
  char *word = malloc(array_string_length + 1);
  rb_encoding *enc = rb_enc_get(pg_array_string);

  int index = 1;

  VALUE return_value = read_array(&index, c_pg_array_string, array_string_length, word, enc);
  free(word);
  return return_value;
}

VALUE read_array(int *index, char *c_pg_array_string, int array_string_length, char *word, rb_encoding *enc)
{
  /* Return value: array */
  VALUE array;
  int word_index = 0;

  /* The current character in the input string. */
  char c;

  /*  0: Currently outside a quoted string, current word never quoted
   *  1: Currently inside a quoted string
   * -1: Currently outside a quoted string, current word previously quoted */
  int openQuote = 0;

  /* Inside quoted input means the next character should be treated literally,
   * instead of being treated as a metacharacter.
   * Outside of quoted input, means that the word shouldn't be pushed to the array,
   * used when the last entry was a subarray (which adds to the array itself). */
  int escapeNext = 0;

  array = rb_ary_new();

  /* Special case the empty array, so it doesn't need to be handled manually inside
   * the loop. */
  if(((*index) < array_string_length) && c_pg_array_string[(*index)] == '}') 
  {
    return array;
  }

  for(;(*index) < array_string_length; ++(*index))
  {
    c = c_pg_array_string[*index];
    if(openQuote < 1)
    {
      if(c == ',' || c == '}')
      {
        if(!escapeNext)
        {
          if(openQuote == 0 && word_index == 4 && !strncmp(word, "NULL", word_index))
          {
            rb_ary_push(array, Qnil);
          }
          else
          {
            rb_ary_push(array, rb_enc_str_new(word, word_index, enc));
          }
        }
        if(c == '}')
        {
          return array;
        }
        escapeNext = 0;
        openQuote = 0;
        word_index = 0;
      }
      else if(c == '"')
      {
        openQuote = 1;
      }
      else if(c == '{')
      {
        (*index)++;
        rb_ary_push(array, read_array(index, c_pg_array_string, array_string_length, word, enc));
        escapeNext = 1;
      }
      else
      {
        word[word_index] = c;
        word_index++;
      }
    }
    else if (escapeNext) {
      word[word_index] = c;
      word_index++;
      escapeNext = 0;
    }
    else if (c == '\\')
    {
      escapeNext = 1;
    }
    else if (c == '"')
    {
      openQuote = -1;
    }
    else
    {
      word[word_index] = c;
      word_index++;
    }
  }

  return array;
}

void Init_pg_array_parser(void) {
  rb_define_method(rb_define_module("PgArrayParser"), "parse_pg_array", parse_pg_array, 1);
}

