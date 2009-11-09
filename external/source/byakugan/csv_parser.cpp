
/* INCLUDING HEADER FILES */

#include "csv_parser.hpp"


/* BEGIN DEFINITION FOR PUBLIC METHODS */
bool csv_parser::init(FILE * input_file_pointer)
{
	input_fp = input_file_pointer;

	if (input_fp == NULL)
	{
		//dprintf("Fatal error : unable to open input file from file pointer\n");

		return false;
	}

	/* Resetting the internal pointer to the beginning of the stream */
	rewind(input_fp);

	more_rows = true;

	_skip_lines();

	return true;
}

bool csv_parser::init(const char * input_file)
{
	const size_t filename_length = strlen(input_file);

	if (!filename_length)
	{
		fprintf(stderr, "Fatal error : invalid input file %s\n", input_file);

		return false;
	}

	input_filename = (char *) malloc(filename_length + 1);

	if (input_filename == NULL)
	{
		//dprintf("Fatal error : unable to allocate memory for file name buffer %s\n", input_file);

		return false;
	}

	memset(input_filename, 0, filename_length + 1);

	strcpy(input_filename, input_file);

	input_fp = fopen(input_file, "r");

	if (input_fp == NULL)
	{
		//dprintf("Fatal error : unable to open input file %s\n", input_file);

		CSV_PARSER_FREE_BUFFER_PTR(input_filename);

		return false;
	}

	more_rows = true;

	_skip_lines();

	return true;
}

void csv_parser::set_enclosed_char(char fields_enclosed_by, enclosure_type_t enclosure_mode)
{
	if (fields_enclosed_by != 0)
	{
		enclosed_char   = fields_enclosed_by;
		enclosed_length = 1U;
		enclosure_type  = enclosure_mode;
	}
}

void csv_parser::set_field_term_char(char fields_terminated_by)
{
	if (fields_terminated_by != 0)
	{
		field_term_char   = fields_terminated_by;
		field_term_length = 1U;
	}
}

void csv_parser::set_line_term_char(char lines_terminated_by)
{
	if (lines_terminated_by != 0)
	{
		line_term_char   = lines_terminated_by;
		line_term_length = 1U;
	}
}

csv_row csv_parser::get_row(void)
{
	csv_row current_row;

	/* This will store the length of the buffer */
	unsigned int line_length = 0U;

	/* Character array buffer for the current record */
	char * line = NULL;

	/* Grab one record */
	_read_single_line(&line, &line_length);

	/* Select the most suitable field extractor based on the enclosure length */
	switch(enclosure_type)
	{
		case ENCLOSURE_NONE : 	 /* The fields are not enclosed by any character */
			_get_fields_without_enclosure(&current_row, line, &line_length);
		break;

		case ENCLOSURE_REQUIRED : /* The fields are enclosed by a character */
			_get_fields_with_enclosure(&current_row, line, &line_length);
		break;

		case ENCLOSURE_OPTIONAL : /* The fields may or may not be enclosed */
			_get_fields_with_optional_enclosure(&current_row, line, &line_length);
		break;

		default :
			_get_fields_with_optional_enclosure(&current_row, line, &line_length);
		break;
	}

	/* Deallocate the current buffer */
	CSV_PARSER_FREE_BUFFER_PTR(line);

	/* Keeps track of how many times this has method has been called */
	record_count++;

	return current_row;
}

/* BEGIN DEFINITION FOR PROTECTED METHODS */


/* BEGIN DEFINITION FOR PRIVATE METHODS */

void csv_parser::_skip_lines(void)
{
	/* Just in case the user accidentally sets ignore_num_lines to a negative number */
	unsigned int number_of_lines_to_ignore = abs((int) ignore_num_lines);

	while(has_more_rows() && number_of_lines_to_ignore)
	{
		const csv_row row = get_row();

		number_of_lines_to_ignore--;
	}

	record_count = 0U;
}

void csv_parser::_get_fields_without_enclosure(csv_row_ptr row, const char * line, const unsigned int * line_length)
{
	char * field = NULL;

	if (*line_length > 0)
	{
		field = (char *) malloc(*line_length);

		memset(field, 0, *line_length);

		register unsigned int field_start   = 0U;
		register unsigned int field_end     = 0U;
		register unsigned int char_pos 		= 0U;

		while(char_pos < *line_length)
		{
			char curr_char = line[char_pos];

			if (curr_char == field_term_char)
			{
				field_end = char_pos;

				const char * field_starts_at = line + field_start;

				/* Field width must exclude field delimiter characters */
				const unsigned int field_width = field_end - field_start;

				/* Copy exactly field_width bytes from field_starts_at to field */
				memcpy(field, field_starts_at, field_width);

				/* This must be a null-terminated character array */
				field[field_width] = 0x00;

				string field_string_obj = field;

				row->push_back(field_string_obj);

				/* This is the starting point of the next field */
				field_start = char_pos + 1;

			} else if (curr_char == line_term_char)
			{
				field_end = char_pos;

				const char * field_starts_at = line + field_start;

				/* Field width must exclude line terminating characters */
				const unsigned int field_width = field_end - field_start;

				/* Copy exactly field_width bytes from field_starts_at to field */
				memcpy(field, field_starts_at, field_width);

				/* This must be a null-terminated character array */
				field[field_width] = 0x00;

				string field_string_obj = field;

				row->push_back(field_string_obj);
			}

			/* Move to the next character in the current line */
			char_pos++;
		}

		/* Deallocate memory for field buffer */
		CSV_PARSER_FREE_BUFFER_PTR(field);
	}
}

void csv_parser::_get_fields_with_enclosure(csv_row_ptr row, const char * line, const unsigned int * line_length)
{
	char * field = NULL;

	if (*line_length > 0)
	{
		field = (char *) malloc(*line_length);

		memset(field, 0, *line_length);

		register unsigned int current_state = 0U;
		register unsigned int field_start   = 0U;
		register unsigned int field_end     = 0U;
		register unsigned int char_pos 		= 0U;

		while(char_pos < *line_length)
		{
			char curr_char = line[char_pos];

			if (curr_char == enclosed_char)
			{
				current_state++;

				/* Lets find out if the enclosure character encountered is
				 * a 'real' enclosure character or if it is an embedded character that
				 * has been escaped within the field.
				 */
				register char previous_char = 0x00;

				if (char_pos > 0U)
				{
					/* The escaped char will have to be the 2rd or later character. */
					previous_char = line[char_pos - 1];

					if (previous_char == escaped_char)
					{
						--current_state;
					}
				}

				if (current_state == 1U && previous_char != escaped_char)
				{
					/* This marks the beginning of the column */
					field_start = char_pos;

				} else if (current_state == 2U)
				{
					/* We have found the end of the current field */
					field_end = char_pos;

					/* We do not need the enclosure characters */
					const char * field_starts_at = line + field_start + 1U;

					/* Field width must exclude beginning and ending enclosure characters */
					const unsigned int field_width = field_end - field_start - 1U;

					/* Copy exactly field_width bytes from field_starts_at to field */
					memcpy(field, field_starts_at, field_width);

					/* This must be a null-terminated character array */
					field[field_width] = 0x00;

					string field_string_obj = field;

					row->push_back(field_string_obj);

					/* Reset the state to zero value for the next field */
					current_state = 0U;
				}
			}

			/* Move to the next character in the current line */
			char_pos++;
		}

		/* If no enclosures were found in this line, the entire line becomes the only field. */
		if (0 == row->size())
		{
			string entire_line = line;

			row->push_back(entire_line);

		} else if (current_state == 1U)
		{
			/* The beginning enclosure character was found but
			 * we could not locate the closing enclosure in the current line
			 * So we need to copy the remainder of the line into the last field.
			 */

			/* We do not need the starting enclosure character */
			const char * field_starts_at = line + field_start + 1U;

			/* Field width must exclude beginning characters */
			const unsigned int field_width = *line_length - field_start - 1U;

			/* Copy exactly field_width bytes from field_starts_at to field */
			memcpy(field, field_starts_at, field_width);

			/* This must be a null-terminated character array */
			field[field_width] = 0x00;

			string field_string_obj = field;

			row->push_back(field_string_obj);
		}

		/* Release the buffer for the field */
		CSV_PARSER_FREE_BUFFER_PTR(field);
	}
}

void csv_parser::_get_fields_with_optional_enclosure(csv_row_ptr row, const char * line, const unsigned int * line_length)
{
	char * field = NULL;

	/*
	 * How to extract the fields, when the enclosure char is optional.
	 *
	 * This is very similar to parsing the document without enclosure but with the following conditions.
	 *
	 * If the beginning char is an enclosure character, adjust the starting position of the string by + 1.
	 * If the ending char is an enclosure character, adjust the ending position by -1
	 */
	if (*line_length > 0)
	{
		field = (char *) malloc(*line_length);

		memset(field, 0, *line_length);

		register unsigned int field_start   = 0U;
		register unsigned int field_end     = 0U;
		register unsigned int char_pos 		= 0U;

		while(char_pos < *line_length)
		{
			char curr_char = line[char_pos];

			if (curr_char == field_term_char)
			{
				field_end = char_pos;

				const char * field_starts_at = line + field_start;

				/* Field width must exclude field delimiter characters */
				unsigned int field_width = field_end - field_start;

				const char line_first_char = field_starts_at[0];
				const char line_final_char = field_starts_at[field_width - 1];

				/* If the enclosure char is found at either ends of the string */
				unsigned int first_adjustment = (line_first_char == enclosed_char) ? 1U : 0U;
				unsigned int final_adjustment = (line_final_char == enclosed_char) ? 2U : 0U;

				/* We do not want to have any negative or zero field widths */
				field_width = (field_width > 2U) ? (field_width - final_adjustment) : field_width;

				/* Copy exactly field_width bytes from field_starts_at to field */
				memcpy(field, field_starts_at + first_adjustment, field_width);

				/* This must be a null-terminated character array */
				field[field_width] = 0x00;

				string field_string_obj = field;

				row->push_back(field_string_obj);

				/* This is the starting point of the next field */
				field_start = char_pos + 1;

			} else if (curr_char == line_term_char)
			{
				field_end = char_pos;

				const char * field_starts_at = line + field_start;

				/* Field width must exclude line terminating characters */
				unsigned int field_width = field_end - field_start;

				const char line_first_char = field_starts_at[0];
				const char line_final_char = field_starts_at[field_width - 1];

				/* If the enclosure char is found at either ends of the string */
				unsigned int first_adjustment = (line_first_char == enclosed_char) ? 1U : 0U;
				unsigned int final_adjustment = (line_final_char == enclosed_char) ? 2U : 0U;

				/* We do not want to have any negative or zero field widths */
				field_width = (field_width > 2U) ? (field_width - final_adjustment) : field_width;

				/* Copy exactly field_width bytes from field_starts_at to field */
				memcpy(field, field_starts_at + first_adjustment, field_width);

				/* This must be a null-terminated character array */
				field[field_width] = 0x00;

				string field_string_obj = field;

				row->push_back(field_string_obj);
			}

			/* Move to the next character in the current line */
			char_pos++;
		}

		/* Deallocate memory for field buffer */
		CSV_PARSER_FREE_BUFFER_PTR(field);
	}
}

void csv_parser::_read_single_line(char ** buffer, unsigned int * buffer_len)
{
	long int original_pos = ftell(input_fp);
	long int current_pos  = original_pos;

	register int current_char = 0;

	/* Checking one character at a time until the end of a line is found */
	while(true)
	{
		current_char = fgetc(input_fp);

		if (current_char == EOF)
		{
			/* We have reached the end of the file */
			more_rows = false;

			break;

		} else if (current_char == line_term_char)
		{
			/* We have reached the end of the row */
			current_pos++;

			break;

		} else {

			current_pos++;
		}
	}

	/* Let's try to peek one character ahead to see if we are at the end of the file */
	if (more_rows)
	{
		current_char = fgetc(input_fp);

		more_rows = (current_char == EOF) ? false : true;
	}

	/* Find out how long this row is */
	const size_t length_of_row = current_pos - original_pos;

	if (length_of_row > 0)
	{
		*buffer_len = length_of_row * sizeof(char) + 1;

		*buffer = (char *) realloc(*buffer, *buffer_len);

		memset(*buffer, 0, *buffer_len);

		/* Reset the internal pointer to the original position */
		fseek(input_fp, original_pos, SEEK_SET);

		/* Copy the contents of the line into the buffer */
		fread(*buffer, 1, length_of_row, input_fp);
	}
}
