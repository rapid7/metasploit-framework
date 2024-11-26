/**
 * csv_parser Header File
 *
 * This object is used to parse text documents that are delimited by some
 * type of character. Some of the common ones use spaces, tabs, commas and semi-colons.
 *
 * This is a list of common characters encountered by this program
 *
 * This list was prepared from the data from http://www.asciitable.com
 *
 * @li DEC is how it would be represented in decimal form (base 10)
 * @li HEX is how it would be represented in hexadecimal format (base 16)
 *
 * @li	DEC	HEX		Character Name
 * @li	0	0x00	null
 * @li	9	0x09	horizontal tab
 * @li	10	0x0A	line feed, new line
 * @li	13	0x0D	carriage return
 * @li	27	0x1B	escape
 * @li	32	0x20	space
 * @li	33	0x21	double quote
 * @li	39	0x27	single quote
 * @li	44	0x2C	comma
 * @li	92	0x5C	backslash
 *
 * @author Israel Ekpo <israel.ekpo@israelekpo.com>
 */

#ifndef CSV_PARSER_HPP_INCLUDED

#define CSV_PARSER_HPP_INCLUDED

#define LIBCSV_PARSER_MAJOR_VERSION 1

#define LIBCSV_PARSER_MINOR_VERSION 0

#define LIBCSV_PARSER_PATCH_VERSION 0

#define LIBCSV_PARSER_VERSION_NUMBER 10000

/* C++ header files */
#include <string>
#include <vector>


/* C header files */
#include <cstdio>
#include <cstring>
#include <cstdlib>

using namespace std;

/**
 * @typedef csv_row
 *
 * Data structure used to represent a record.
 *
 * This is an alias for vector <string>
 */
typedef vector <string> csv_row;

/**
 * @typedef csv_row_ptr
 *
 * Pointer to a csv_row object
 *
 * Expands to vector <string> *
 */
typedef csv_row * csv_row_ptr;

/**
 * @typedef enclosure_type_t
 *
 * This enum type is used to set the mode in which the CSV file is parsed.
 *
 * @li ENCLOSURE_NONE 		(1) means the CSV file does not use any enclosure characters for the fields
 * @li ENCLOSURE_REQUIRED 	(2) means the CSV file requires enclosure characters for all the fields
 * @li ENCLOSURE_OPTIONAL 	(3) means the use of enclosure characters for the fields is optional
 *
 * The ENCLOSURE_TYPE_BEGIN and ENCLOSURE_TYPE_END members of this enum definition are never to be used.
 */
typedef enum
{
	ENCLOSURE_TYPE_BEGIN = 0,
	ENCLOSURE_NONE       = 1,
	ENCLOSURE_REQUIRED   = 2,
	ENCLOSURE_OPTIONAL   = 3,
	ENCLOSURE_TYPE_END

} enclosure_type_t;

/**
 * @def CSV_PARSER_FREE_BUFFER_PTR(ptr)
 *
 * Used to deallocate buffer pointers
 *
 * It deallocates the pointer only if it is not null
 */
#define CSV_PARSER_FREE_BUFFER_PTR(ptr)	\
if (ptr != NULL)						\
{										\
	free(ptr);							\
										\
	ptr = NULL;							\
}

/**
 * @def CSV_PARSER_FREE_FILE_PTR(fptr)
 *
 * Used to close open file handles
 *
 * It closes the file only if it is not null
 */
#define CSV_PARSER_FREE_FILE_PTR(fptr)	\
if (fptr != NULL)						\
{										\
	fclose(fptr);						\
										\
	fptr = NULL;						\
}

/**
 * @class csv_parser
 *
 * The csv_parser object
 *
 * Used to parse text files to extract records and fields.
 *
 * We are making the following assumptions :
 *
 * @li The record terminator is only one character in length.
 * @li The field terminator is only one character in length.
 * @li The fields are enclosed by single characters, if any.
 *
 * @li The parser can handle documents where fields are always enclosed, not enclosed at all or optionally enclosed.
 * @li When fields are strictly all enclosed, there is an assumption that any enclosure characters within the field are escaped by placing a backslash in front of the enclosure character.
 *
 * The CSV files can be parsed in 3 modes.
 * @li (a) No enclosures
 * @li (b) Fields always enclosed.
 * @li (c) Fields optionally enclosed.
 *
 * For option (c) when the enclosure character is optional, if an enclosure character is spotted at either the beginning
 * or the end of the string, it is assumed that the field is enclosed.
 *
 * The csv_parser::init() method can accept a character array as the path to the CSV file.
 * Since it is overloaded, it can also accept a FILE pointer to a stream that is already open for reading.
 *
 * The set_enclosed_char() method accepts the field enclosure character as the first parameter and the enclosure mode as the second parameter which
 * controls how the text file is going to be parsed.
 *
 * @see csv_parser::set_enclosed_char()
 * @see enclosure_type_t
 *
 * @todo Add ability to parse files where fields/columns are terminated by strings instead of just one char.
 * @todo Add ability to set strings where lines start by. Currently lines do not have any starting char or string.
 * @todo Add ability to set strings where line end by. Currently lines can only end with a single char.
 * @todo Add ability to accept other escape characters besides the backslash character 0x5C.
 * @todo More support for improperly formatted CSV data files.
 *
 * @author Israel Ekpo <israel.ekpo@israelekpo.com>
 */
class csv_parser
{

public :

	/**
	 * Class constructor
	 *
	 * This is the default constructor.
	 *
	 * All the internal attributes are initialized here
	 *
	 * @li The enclosure character is initialized to NULL 0x00.
	 * @li The escape character is initialized to the backslash character 0x5C.
	 * @li The field delimiter character is initialized to a comma 0x2C.
	 * @li The record delimiter character is initialized to a new line character 0x0A.
	 *
	 * @li The lengths of all the above-mentioned fields are initialized to 0,1,1 and 1 respectively.
	 * @li The number of records to ignore is set to zero.
	 * @li The more_rows internal attribute is set to false.
	 * @li The pointer to the CSV input file is initialized to NULL
	 * @li The pointer to the buffer for the file name is also initialized to NULL
	 */
	csv_parser() : enclosed_char(0x00), 	escaped_char(0x5C),
				   field_term_char(0x2C),  	line_term_char(0x0A),
				   enclosed_length(0U),    	escaped_length(1U),
				   field_term_length(1U),  	line_term_length(1U),
				   ignore_num_lines(0U),   	record_count(0U),
				   input_fp(NULL),		   	input_filename(NULL),
				   enclosure_type(ENCLOSURE_NONE),
				   more_rows(false)
				   { }

	/**
	 * Class destructor
	 *
	 * In the class destructor the file pointer to the input CSV file is closed and
	 * the buffer to the input file name is also deallocated.
	 *
	 * @see csv_parser::input_fp
	 * @see csv_parser::input_filename
	 */
	~csv_parser()
	{
		CSV_PARSER_FREE_FILE_PTR(input_fp);

		CSV_PARSER_FREE_BUFFER_PTR(input_filename);
	}

	/**
	 * Initializes the current object
	 *
	 * This init method accepts a pointer to the CSV file that has been opened for reading
	 *
	 * It also resets the file pointer to the beginning of the stream
	 *
	 * @overload bool init(FILE * input_file_pointer)
	 * @param[in] input_file_pointer
	 * @return bool Returns true on success and false on error.
	 */
	bool init(FILE * input_file_pointer);

	/**
	 * Initializes the current object
	 *
	 * @li This init method accepts a character array as the path to the csv file.
	 * @li It sets the value of the csv_parser::input_filename property.
	 * @li Then it creates a pointer to the csv_parser::input_fp property.
	 *
	 * @overload bool init(const char * input_filename)
	 * @param[in] input_filename
	 * @return bool Returns true on success and false on error.
	 */
	bool init(const char * input_filename);

	/**
	 * Defines the Field Enclosure character used in the Text File
	 *
	 * Setting this to NULL means that the enclosure character is optional.
	 *
	 * If the enclosure is optional, there could be fields that are enclosed, and fields that are not enclosed within the same line/record.
	 *
	 * @param[in] fields_enclosed_by The character used to enclose the fields.
	 * @param[in] enclosure_mode How the CSV file should be parsed.
	 * @return void
	 */
	void set_enclosed_char(char fields_enclosed_by, enclosure_type_t enclosure_mode);

	/**
	 * Defines the Field Delimiter character used in the text file
	 *
	 * @param[in] fields_terminated_by
	 * @return void
	 */
	void set_field_term_char(char fields_terminated_by);

	/**
	 * Defines the Record Terminator character used in the text file
	 *
	 * @param[in] lines_terminated_by
	 * @return void
	 */
	void set_line_term_char(char lines_terminated_by);

	/**
	 * Returns whether there is still more data
	 *
	 * This method returns a boolean value indicating whether or not there are
	 * still more records to be extracted in the current file being parsed.
	 *
	 * Call this method to see if there are more rows to retrieve before invoking csv_parser::get_row()
	 *
	 * @see csv_parser::get_row()
	 * @see csv_parser::more_rows
	 *
	 * @return bool Returns true if there are still more rows and false if there is not.
	 */
	bool has_more_rows(void)
	{
		return more_rows;
	}

	/**
	 * Defines the number of records to discard
	 *
	 * The number of records specified will be discarded during the parsing process.
	 *
	 * @see csv_parser::_skip_lines()
	 * @see csv_parser::get_row()
	 * @see csv_parser::has_more_rows()
	 *
	 * @param[in] lines_to_skip How many records should be skipped
	 * @return void
	 */
	void set_skip_lines(unsigned int lines_to_skip)
	{
		ignore_num_lines = lines_to_skip;
	}

	/**
	 * Return the current row from the CSV file
	 *
	 * The row is returned as a vector of string objects.
	 *
	 * This method should be called only if csv_parser::has_more_rows() is true
	 *
	 * @see csv_parser::has_more_rows()
	 * @see csv_parser::get_record_count()
	 * @see csv_parser::reset_record_count()
	 * @see csv_parser::more_rows
	 *
	 * @return csv_row A vector type containing an array of strings
	 */
	csv_row get_row(void);

	/**
	 * Returns the number of times the csv_parser::get_row() method has been invoked
	 *
	 * @see csv_parser::reset_record_count()
	 * @return unsigned int The number of times the csv_parser::get_row() method has been invoked.
	 */
	unsigned int get_record_count(void)
	{
		return record_count;
	}

	/**
	 * Resets the record_count internal attribute to zero
	 *
	 * This may be used if the object is reused multiple times.
	 *
	 * @see csv_parser::record_count
	 * @see csv_parser::get_record_count()
	 * @return void
	 */
	void reset_record_count(void)
	{
		record_count = 0U;
	}

private :

	/**
	 * Ignores N records in the CSV file
	 *
	 * Where N is the value of the csv_parser::ignore_num_lines internal property.
	 *
	 * The number of lines skipped can be defined by csv_parser::set_skip_lines()
	 *
	 * @see csv_parser::set_skip_lines()
	 *
	 * @return void
	 */
	void _skip_lines(void);

	/**
	 * Reads a Single Line
	 *
	 * Reads a single record into the buffer passed by reference to the method
	 *
	 * @param[in,out] buffer A pointer to a character array for the current line.
	 * @param[out] buffer_len A pointer to an integer storing the length of the buffer.
	 * @return void
	 */
	void _read_single_line(char ** buffer, unsigned int * buffer_len);

	/**
	 * Extracts the fields without enclosures
	 *
	 * This is used when the enclosure character is not set
	 * @param[out] row The vector of strings
	 * @param[in] line The character array buffer containing the current record/line
	 * @param[in] line_length The length of the buffer
	 */
	void _get_fields_without_enclosure(csv_row_ptr row, const char * line, const unsigned int * line_length);

	/**
	 * Extracts the fields with enclosures
	 *
	 * This is used when the enclosure character is set.
	 *
	 * @param[out] row The vector of strings
	 * @param[in] line The character array buffer containing the current record/line
	 * @param[in] line_length The length of the buffer
	 */
	void _get_fields_with_enclosure(csv_row_ptr row, const char * line, const unsigned int * line_length);

	/**
	 * Extracts the fields when enclosure is optional
	 *
	 * This is used when the enclosure character is optional
	 *
	 * Hence, there could be fields that use it, and fields that don't.
	 *
	 * @param[out] row The vector of strings
	 * @param[in] line The character array buffer containing the current record/line
	 * @param[in] line_length The length of the buffer
	 */
	void _get_fields_with_optional_enclosure(csv_row_ptr row, const char * line, const unsigned int * line_length);

protected :

	/**
	 * The enclosure character
	 *
	 * If present or used for a field it is assumed that both ends of the fields are wrapped.
	 *
	 * This is that single character used in the document to wrap the fields.
	 *
	 * @see csv_parser::_get_fields_without_enclosure()
	 * @see csv_parser::_get_fields_with_enclosure()
	 * @see csv_parser::_get_fields_with_optional_enclosure()
	 *
	 * @var enclosed_char
	 */
	char enclosed_char;

	/**
	 * The escape character
	 *
	 * For now the only valid escape character allowed is the backslash character 0x5C
	 *
	 * This is only important when the enclosure character is required or optional.
	 *
	 * This is the backslash character used to escape enclosure characters found within the fields.
	 *
	 * @see csv_parser::_get_fields_with_enclosure()
	 * @see csv_parser::_get_fields_with_optional_enclosure()
	 * @todo Update the code to accept other escape characters besides the backslash
	 *
	 * @var escaped_char
	 */
	char escaped_char;

	/**
	 * The field terminator
	 *
	 * This is the single character used to mark the end of a column in the text file.
	 *
	 * Common characters used include the comma, tab, and semi-colons.
	 *
	 * This is the single character used to separate fields within a record.
	 *
	 * @var field_term_char
	 */
	char field_term_char;

	/**
	 * The record terminator
	 *
	 * This is the single character used to mark the end of a record in the text file.
	 *
	 * The most popular one is the new line character however it is possible to use others as well.
	 *
	 * This is the single character used to mark the end of a record
	 *
	 * @see csv_parser::get_row()
	 *
	 * @var line_term_char
	 */
	char line_term_char;

	/**
	 * Enclosure length
	 *
	 * This is the length of the enclosure character
	 *
	 * @see csv_parser::csv_parser()
	 * @see csv_parser::set_enclosed_char()
	 *
	 * @var enclosed_length
	 */
	unsigned int enclosed_length;

	/**
	 * The length of the escape character
	 *
	 * Right now this is really not being used.
	 *
	 * It may be used in future versions of the object.
	 *
	 * @todo Update the code to accept other escape characters besides the backslash
	 *
	 * @var escaped_length
	 */
	unsigned int escaped_length;

	/**
	 * Length of the field terminator
	 *
	 * For now this is not being used. It will be used in future versions of the object.
	 *
	 * @var field_term_length
	 */
	unsigned int field_term_length;

	/**
	 * Length of the record terminator
	 *
	 * For now this is not being used. It will be used in future versions of the object.
	 *
	 * @var line_term_length
	 */
	unsigned int line_term_length;

	/**
	 * Number of records to discard
	 *
	 * This variable controls how many records in the file are skipped before parsing begins.
	 *
	 * @see csv_parser::_skip_lines()
	 * @see csv_parser::set_skip_lines()
	 *
	 * @var ignore_num_lines
	 */
	unsigned int ignore_num_lines;

	/**
	 * Number of times the get_row() method has been called
	 *
	 * @see csv_parser::get_row()
	 * @var record_count
	 */
	unsigned int record_count;

	/**
	 * The CSV File Pointer
	 *
	 * This is the pointer to the CSV file
	 *
	 * @var input_fp
	 */
	FILE * input_fp;

	/**
	 * Buffer to input file name
	 *
	 * This buffer is used to store the name of the file that is being parsed
	 *
	 * @var input_filename
	 */
	char * input_filename;

	/**
	 * Mode in which the CSV file will be parsed
	 *
	 * The various values are explained below
	 *
	 * @li ENCLOSURE_NONE 		(1) means the CSV file does not use any enclosure characters for the fields
	 * @li ENCLOSURE_REQUIRED 	(2) means the CSV file requires enclosure characters for all the fields
	 * @li ENCLOSURE_OPTIONAL 	(3) means the use of enclosure characters for the fields is optional
	 *
	 * @see csv_parser::get_row()
	 * @see csv_parser::_read_single_line()
	 * @see csv_parser::_get_fields_without_enclosure()
	 * @see csv_parser::_get_fields_with_enclosure()
	 * @see csv_parser::_get_fields_with_optional_enclosure()
	 *
	 * @var enclosure_type
	 */
	enclosure_type_t enclosure_type;

	/**
	 * There are still more records to parse
	 *
	 * This boolean property is an internal indicator of whether there are still records in the
	 * file to be parsed.
	 *
	 * @see csv_parser::has_more_rows()
	 * @var more_rows
	 */
	bool more_rows;

}; /* class csv_parser */

#endif /* CSV_PARSER_HPP_INCLUDED */
