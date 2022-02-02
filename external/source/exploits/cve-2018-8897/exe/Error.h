#pragma once

#define ERROR( msg ) \
{SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 12 ); \
printf( "\n[[[[[[        " msg "        ]]]]]]\n\n" ); \
system( "pause" ); \
exit( 0 );}


#define assert( cond ) if( !(cond) ) ERROR( "Assert Failed: " #cond  )