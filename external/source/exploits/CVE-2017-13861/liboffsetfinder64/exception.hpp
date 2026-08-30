//
//  exception.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef exception_hpp
#define exception_hpp

#include <string>

namespace tihmstar {
    class exception : public std::exception{
        std::string _err;
        int _code;
        std::string _build_commit_count;
        std::string _build_commit_sha;
        std::string _filename;
    public:
        exception(int code, std::string err, std::string filename);
        
        //custom error can be used
        const char *what();
        
        /*
         -first lowest two bytes of code is sourcecode line
         -next two bytes is strlen of filename in which error happened
         */
        int code() const;
        
        //Information about build
        const std::string& build_commit_count() const;
        const std::string& build_commit_sha() const;
    };
    
    //custom exceptions for makeing it easy to catch
    class out_of_range : public exception{
    public:
        out_of_range(std::string err);
    };
    
    class symbol_not_found : public exception{
    public:
        symbol_not_found(int code, std::string sym, std::string filename);
    };
    
    class load_command_not_found : public exception{
        int _cmd;
    public:
        int cmd() const;
        load_command_not_found(int code, int cmd, std::string filename);
    };
    
    class symtab_not_found : public exception{
    public:
        symtab_not_found(int code, std::string err, std::string filename);
    };
    
    class limit_reached : public exception{
    public:
        limit_reached(int code, std::string err, std::string filename);
    };
    
    class bad_branch_destination : public exception{
    public:
        bad_branch_destination(int code, std::string err, std::string filename);
    };
    
};

#endif /* exception_hpp */
