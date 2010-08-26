# a glorified C pre-processor parser

import sys, re, string
from utils import *
from defaults import *

debugTokens             = False
debugDirectiveTokenizer = False
debugLineParsing        = False
debugCppExpr            = False
debugOptimIf01          = False

#####################################################################################
#####################################################################################
#####                                                                           #####
#####           C P P   T O K E N S                                             #####
#####                                                                           #####
#####################################################################################
#####################################################################################

# the list of supported C-preprocessor tokens
# plus a couple of C tokens as well
tokEOF       = "\0"
tokLN        = "\n"
tokSTRINGIFY = "#"
tokCONCAT    = "##"
tokLOGICAND  = "&&"
tokLOGICOR   = "||"
tokSHL       = "<<"
tokSHR       = ">>"
tokEQUAL     = "=="
tokNEQUAL    = "!="
tokLT        = "<"
tokLTE       = "<="
tokGT        = ">"
tokGTE       = ">="
tokELLIPSIS  = "..."
tokSPACE     = " "
tokDEFINED   = "defined"
tokLPAREN    = "("
tokRPAREN    = ")"
tokNOT       = "!"
tokPLUS      = "+"
tokMINUS     = "-"
tokMULTIPLY  = "*"
tokDIVIDE    = "/"
tokMODULUS   = "%"
tokBINAND    = "&"
tokBINOR     = "|"
tokBINXOR    = "^"
tokCOMMA     = ","
tokLBRACE    = "{"
tokRBRACE    = "}"
tokARROW     = "->"
tokINCREMENT = "++"
tokDECREMENT = "--"
tokNUMBER    = "<number>"
tokIDENT     = "<ident>"
tokSTRING    = "<string>"

class Token:
    """a simple class to hold information about a given token.
       each token has a position in the source code, as well as
       an 'id' and a 'value'. the id is a string that identifies
       the token's class, while the value is the string of the
       original token itself.

       for example, the tokenizer concatenates a series of spaces
       and tabs as a single tokSPACE id, whose value if the original
       spaces+tabs sequence."""

    def __init__(self):
        self.id     = None
        self.value  = None
        self.lineno = 0
        self.colno  = 0

    def set(self,id,val=None):
        self.id = id
        if val:
            self.value = val
        else:
            self.value = id
        return None

    def copyFrom(self,src):
        self.id     = src.id
        self.value  = src.value
        self.lineno = src.lineno
        self.colno  = src.colno

    def __repr__(self):
        if self.id == tokIDENT:
            return "(ident %s)" % self.value
        if self.id == tokNUMBER:
            return "(number %s)" % self.value
        if self.id == tokSTRING:
            return "(string '%s')" % self.value
        if self.id == tokLN:
            return "<LN>"
        if self.id == tokEOF:
            return "<EOF>"
        if self.id == tokSPACE and self.value == "\\":
            # this corresponds to a trailing \ that was transformed into a tokSPACE
            return "<\\>"

        return self.id

    def __str__(self):
        if self.id == tokIDENT:
            return self.value
        if self.id == tokNUMBER:
            return self.value
        if self.id == tokSTRING:
            return self.value
        if self.id == tokEOF:
            return "<EOF>"
        if self.id == tokSPACE:
            if self.value == "\\":  # trailing \
                return "\\\n"
            else:
                return self.value

        return self.id

class BadExpectedToken(Exception):
    def __init__(self,msg):
        print msg

#####################################################################################
#####################################################################################
#####                                                                           #####
#####          C P P   T O K E N   C U R S O R                                  #####
#####                                                                           #####
#####################################################################################
#####################################################################################

class TokenCursor:
    """a small class to iterate over a list of Token objects"""
    def __init__(self,tokens):
        self.tokens = tokens
        self.n      = 0
        self.count  = len(tokens)

    def set(self,n):
        """set the current position"""
        if n < 0:
            n = 0
        if n > self.count:
            n = self.count
        self.n = n

    def peekId(self):
        """retrieve the id of the current token"""
        if (self.n >= self.count):
            return None
        return self.tokens[self.n].id

    def peek(self):
        """retrieve the current token. does not change position"""
        if (self.n >= self.count):
            return None
        return self.tokens[self.n]

    def skip(self):
        """increase current token position"""
        if (self.n < self.count):
            self.n += 1

    def skipSpaces(self):
        """skip over all space tokens, this includes tokSPACE and tokLN"""
        while 1:
            tok = self.peekId()
            if tok != tokSPACE and tok != tokLN:
                break
            self.skip()

    def skipIfId(self,id):
        """skip an optional token"""
        if self.peekId() == id:
            self.skip()

    def expectId(self,id):
        """raise an exception if the current token hasn't a given id.
           otherwise skip over it"""
        tok = self.peek()
        if tok.id != id:
            raise BadExpectedToken, "%d:%d: '%s' expected, received '%s'" % (tok.lineno, tok.colno, id, tok.id)
        self.skip()

    def remain(self):
        """return the list of remaining tokens"""
        return self.tokens[self.n:]


#####################################################################################
#####################################################################################
#####                                                                           #####
#####           C P P   T O K E N I Z E R                                       #####
#####                                                                           #####
#####################################################################################
#####################################################################################

# list of long symbols, i.e. those that take more than one characters
cppLongSymbols = [ tokCONCAT, tokLOGICAND, tokLOGICOR, tokSHL, tokSHR, tokELLIPSIS, tokEQUAL,\
                   tokNEQUAL, tokLTE, tokGTE, tokARROW, tokINCREMENT, tokDECREMENT ]

class CppTokenizer:
    """an abstract class used to convert some input text into a list
       of tokens. real implementations follow and differ in the format
       of the input text only"""

    def __init__(self):
        """initialize a new CppTokenizer object"""
        self.eof  = False  # end of file reached ?
        self.text = None   # content of current line, with final \n stripped
        self.line = 0      # number of current line
        self.pos  = 0      # current character position in current line
        self.len  = 0      # length of current line text
        self.held = Token()

    def setLineText(self,line):
        """set the content of the (next) current line. should be called
           by fillLineText() in derived classes"""
        self.text = line
        self.len  = len(line)
        self.pos  = 0

    def fillLineText(self):
        """refresh the content of 'line' with a new line of input"""
        # to be overriden
        self.eof = True

    def markPos(self,tok):
        """mark the position of the current token in the source file"""
        if self.eof or self.pos > self.len:
            tok.lineno = self.line + 1
            tok.colno  = 0
        else:
            tok.lineno = self.line
            tok.colno  = self.pos

    def peekChar(self):
        """return the current token under the cursor without moving it"""
        if self.eof:
            return tokEOF

        if self.pos > self.len:
            self.pos   = 0
            self.line += 1
            self.fillLineText()
            if self.eof:
                return tokEOF

        if self.pos == self.len:
            return tokLN
        else:
            return self.text[self.pos]

    def peekNChar(self,n):
        """try to peek the next n chars on the same line"""
        if self.pos + n > self.len:
            return None
        return self.text[self.pos:self.pos+n]

    def skipChar(self):
        """increment the token cursor position"""
        if not self.eof:
            self.pos += 1

    def skipNChars(self,n):
        if self.pos + n <= self.len:
            self.pos += n
        else:
            while n > 0:
                self.skipChar()
                n -= 1

    def nextChar(self):
        """retrieve the token at the current cursor position, then skip it"""
        result = self.peekChar()
        self.skipChar()
        return  result

    def getEscape(self):
        # try to get all characters after a backslash (\)
        result = self.nextChar()
        if result == "0":
            # octal number ?
            num = self.peekNChar(3)
            if num != None:
                isOctal = True
                for d in num:
                    if not d in "01234567":
                        isOctal = False
                        break
                if isOctal:
                    result += num
                    self.skipNChars(3)
        elif result == "x" or result == "X":
            # hex number ?
            num = self.peekNChar(2)
            if num != None:
                isHex = True
                for d in num:
                    if not d in "012345678abcdefABCDEF":
                        isHex = False
                        break
                if isHex:
                    result += num
                    self.skipNChars(2)
        elif result == "u" or result == "U":
            # unicode char ?
            num = self.peekNChar(4)
            if num != None:
                isHex = True
                for d in num:
                    if not d in "012345678abcdefABCDEF":
                        isHex = False
                        break
                if isHex:
                    result += num
                    self.skipNChars(4)

        return result

    def nextRealToken(self,tok):
        """return next CPP token, used internally by nextToken()"""
        c = self.nextChar()
        if c == tokEOF or c == tokLN:
            return tok.set(c)

        if c == '/':
            c = self.peekChar()
            if c == '/':   # C++ comment line
                self.skipChar()
                while 1:
                    c = self.nextChar()
                    if c == tokEOF or c == tokLN:
                        break
                return tok.set(tokLN)
            if c == '*':   # C comment start
                self.skipChar()
                value = "/*"
                prev_c = None
                while 1:
                    c = self.nextChar()
                    if c == tokEOF:
                        #print "## EOF after '%s'" % value
                        return tok.set(tokEOF,value)
                    if c == '/' and prev_c == '*':
                        break
                    prev_c = c
                    value += c

                value += "/"
                #print "## COMMENT: '%s'" % value
                return tok.set(tokSPACE,value)
            c = '/'

        if c.isspace():
            while 1:
                c2 = self.peekChar()
                if c2 == tokLN or not c2.isspace():
                    break
                c += c2
                self.skipChar()
            return tok.set(tokSPACE,c)

        if c == '\\':
            if debugTokens:
                print "nextRealToken: \\ found, next token is '%s'" % repr(self.peekChar())
            if self.peekChar() == tokLN:   # trailing \
                # eat the tokLN
                self.skipChar()
                # we replace a trailing \ by a tokSPACE whose value is
                # simply "\\". this allows us to detect them later when
                # needed.
                return tok.set(tokSPACE,"\\")
            else:
                # treat as a single token here ?
                c +=self.getEscape()
                return tok.set(c)

        if c == "'":  # chars
            c2 = self.nextChar()
            c += c2
            if c2 == '\\':
                c += self.getEscape()

            while 1:
                c2 = self.nextChar()
                if c2 == tokEOF:
                    break
                c += c2
                if c2 == "'":
                    break

            return tok.set(tokSTRING, c)

        if c == '"':  # strings
            quote = 0
            while 1:
                c2  = self.nextChar()
                if c2 == tokEOF:
                    return tok.set(tokSTRING,c)

                c += c2
                if not quote:
                    if c2 == '"':
                        return tok.set(tokSTRING,c)
                    if c2 == "\\":
                        quote = 1
                else:
                    quote = 0

        if c >= "0" and c <= "9":  # integers ?
            while 1:
                c2 = self.peekChar()
                if c2 == tokLN or (not c2.isalnum() and c2 != "_"):
                    break
                c += c2
                self.skipChar()
            return tok.set(tokNUMBER,c)

        if c.isalnum() or c == "_":  # identifiers ?
            while 1:
                c2 = self.peekChar()
                if c2 == tokLN or (not c2.isalnum() and c2 != "_"):
                    break
                c += c2
                self.skipChar()
            if c == tokDEFINED:
                return tok.set(tokDEFINED)
            else:
                return tok.set(tokIDENT,c)

        # check special symbols
        for sk in cppLongSymbols:
            if c == sk[0]:
                sklen = len(sk[1:])
                if self.pos + sklen <= self.len and \
                   self.text[self.pos:self.pos+sklen] == sk[1:]:
                    self.pos += sklen
                    return tok.set(sk)

        return tok.set(c)

    def nextToken(self,tok):
        """return the next token from the input text. this function
           really updates 'tok', and does not return a new one"""
        self.markPos(tok)
        self.nextRealToken(tok)

    def getToken(self):
        tok = Token()
        self.nextToken(tok)
        if debugTokens:
            print "getTokens: %s" % repr(tok)
        return tok

    def toTokenList(self):
        """convert the input text of a CppTokenizer into a direct
           list of token objects. tokEOF is stripped from the result"""
        result = []
        while 1:
            tok = Token()
            self.nextToken(tok)
            if tok.id == tokEOF:
                break
            result.append(tok)
        return result

class CppLineTokenizer(CppTokenizer):
    """a CppTokenizer derived class that accepts a single line of text as input"""
    def __init__(self,line,lineno=1):
        CppTokenizer.__init__(self)
        self.line = lineno
        self.setLineText(line)


class CppLinesTokenizer(CppTokenizer):
    """a CppTokenizer derived class that accepts a list of texdt lines as input.
       the lines must not have a trailing \n"""
    def __init__(self,lines=[],lineno=1):
        """initialize a CppLinesTokenizer. you can later add lines using addLines()"""
        CppTokenizer.__init__(self)
        self.line  = lineno
        self.lines = lines
        self.index = 0
        self.count = len(lines)

        if self.count > 0:
            self.fillLineText()
        else:
            self.eof = True

    def addLine(self,line):
        """add a line to a CppLinesTokenizer. this can be done after tokenization
           happens"""
        if self.count == 0:
            self.setLineText(line)
            self.index = 1
        self.lines.append(line)
        self.count += 1
        self.eof    = False

    def fillLineText(self):
        if self.index < self.count:
            self.setLineText(self.lines[self.index])
            self.index += 1
        else:
            self.eof = True


class CppFileTokenizer(CppTokenizer):
    def __init__(self,file,lineno=1):
        CppTokenizer.__init__(self)
        self.file = file
        self.line = lineno

    def fillLineText(self):
        line = self.file.readline()
        if len(line) > 0:
            if line[-1] == '\n':
                line = line[:-1]
            if len(line) > 0 and line[-1] == "\r":
                line = line[:-1]
            self.setLineText(line)
        else:
            self.eof = True

# Unit testing
#
class CppTokenizerTester:
    """a class used to test CppTokenizer classes"""
    def __init__(self,tokenizer=None):
        self.tokenizer = tokenizer
        self.token     = Token()

    def setTokenizer(self,tokenizer):
        self.tokenizer = tokenizer

    def expect(self,id):
        self.tokenizer.nextToken(self.token)
        tokid = self.token.id
        if tokid == id:
            return
        if self.token.value == id and (tokid == tokIDENT or tokid == tokNUMBER):
            return
        raise BadExpectedToken, "###  BAD TOKEN: '%s' expecting '%s'" % (self.token.id,id)

    def expectToken(self,id,line,col):
        self.expect(id)
        if self.token.lineno != line:
            raise BadExpectedToken, "###  BAD LINENO: token '%s' got '%d' expecting '%d'" % (id,self.token.lineno,line)
        if self.token.colno != col:
            raise BadExpectedToken, "###  BAD COLNO: '%d' expecting '%d'" % (self.token.colno,col)

    def expectTokenVal(self,id,value,line,col):
        self.expectToken(id,line,col)
        if self.token.value != value:
            raise BadExpectedToken, "###  BAD VALUE: '%s' expecting '%s'" % (self.token.value,value)

    def expectList(self,list):
        for item in list:
            self.expect(item)

def test_CppTokenizer():
    print "running CppTokenizer tests"
    tester = CppTokenizerTester()

    tester.setTokenizer( CppLineTokenizer("#an/example  && (01923_xy)") )
    tester.expectList( ["#", "an", "/", "example", tokSPACE, tokLOGICAND, tokSPACE, tokLPAREN, "01923_xy", \
                       tokRPAREN, tokLN, tokEOF] )

    tester.setTokenizer( CppLineTokenizer("FOO(BAR) && defined(BAZ)") )
    tester.expectList( ["FOO", tokLPAREN, "BAR", tokRPAREN, tokSPACE, tokLOGICAND, tokSPACE,
                        tokDEFINED, tokLPAREN, "BAZ", tokRPAREN, tokLN, tokEOF] )

    tester.setTokenizer( CppLinesTokenizer( ["/*", "#", "*/"] ) )
    tester.expectList( [ tokSPACE, tokLN, tokEOF ] )

    tester.setTokenizer( CppLinesTokenizer( ["first", "second"] ) )
    tester.expectList( [ "first", tokLN, "second", tokLN, tokEOF ] )

    tester.setTokenizer( CppLinesTokenizer( ["first second", "  third"] ) )
    tester.expectToken( "first", 1, 0 )
    tester.expectToken( tokSPACE, 1, 5 )
    tester.expectToken( "second", 1, 6 )
    tester.expectToken( tokLN, 1, 12 )
    tester.expectToken( tokSPACE, 2, 0 )
    tester.expectToken( "third", 2, 2 )

    tester.setTokenizer( CppLinesTokenizer( [ "boo /* what the", "hell */" ] ) )
    tester.expectList( [ "boo", tokSPACE ] )
    tester.expectTokenVal( tokSPACE, "/* what the\nhell */", 1, 4 )
    tester.expectList( [ tokLN, tokEOF ] )

    tester.setTokenizer( CppLinesTokenizer( [ "an \\", " example" ] ) )
    tester.expectToken( "an", 1, 0 )
    tester.expectToken( tokSPACE, 1, 2 )
    tester.expectTokenVal( tokSPACE, "\\", 1, 3 )
    tester.expectToken( tokSPACE, 2, 0 )
    tester.expectToken( "example", 2, 1 )
    tester.expectToken( tokLN, 2, 8 )

    return True


#####################################################################################
#####################################################################################
#####                                                                           #####
#####           C P P   E X P R E S S I O N S                                   #####
#####                                                                           #####
#####################################################################################
#####################################################################################

# Cpp expressions are modeled by tuples of the form (op,arg) or (op,arg1,arg2), etc..
# op is an "operator" string

class Expr:
    """a class used to model a CPP expression"""
    opInteger   = "int"
    opIdent     = "ident"
    opCall      = "call"
    opDefined   = "defined"
    opTest      = "?"
    opLogicNot  = "!"
    opNot       = "~"
    opNeg       = "[-]"
    opUnaryPlus = "[+]"
    opAdd = "+"
    opSub = "-"
    opMul = "*"
    opDiv = "/"
    opMod = "%"
    opAnd = "&"
    opOr  = "|"
    opXor = "^"
    opLogicAnd = "&&"
    opLogicOr  = "||"
    opEqual = "=="
    opNotEqual = "!="
    opLess = "<"
    opLessEq = "<="
    opGreater = ">"
    opGreaterEq = ">="
    opShl = "<<"
    opShr = ">>"

    unaries  = [ opLogicNot, opNot, opNeg, opUnaryPlus ]
    binaries = [ opAdd, opSub, opMul, opDiv, opMod, opAnd, opOr, opXor, opLogicAnd, opLogicOr,
                 opEqual, opNotEqual, opLess, opLessEq, opGreater, opGreaterEq ]

    precedences = {
                    opTest: 0,
                    opLogicOr:  1,
                    opLogicNot: 2,
                    opOr : 3,
                    opXor: 4,
                    opAnd: 5,
                    opEqual: 6, opNotEqual: 6,
                    opLess:7, opLessEq:7, opGreater:7, opGreaterEq:7,
                    opShl:8, opShr:8,
                    opAdd:9, opSub:9,
                    opMul:10, opDiv:10, opMod:10,
                    opLogicNot:11,
                    opNot: 12,
                    }

    def __init__(self,op):
        self.op = op

    def __repr__(self):
        return "(%s)" % self.op

    def __str__(self):
        return "operator(%s)" % self.op

    def precedence(self):
        """return the precedence of a given operator"""
        return Expr.precedences.get(self.op, 1000)

    def isUnary(self):
        return self.op in Expr.unaries

    def isBinary(self):
        return self.op in Expr.binaries

    def isDefined(self):
        return self.op is opDefined

    def toInt(self):
        """return the integer value of a given expression. only valid for integer expressions
           will return None otherwise"""
        return None

class IntExpr(Expr):
    def __init__(self,value):
        Expr.__init__(self,opInteger)
        self.arg   = value

    def __repr__(self):
        return "(int %s)" % self.arg

    def __str__(self):
        return self.arg

    def toInt(self):
        s = self.arg  # string value
        # get rid of U or L suffixes
        while len(s) > 0 and s[-1] in "LUlu":
            s = s[:-1]
        return string.atoi(s)

class IdentExpr(Expr):
    def __init__(self,name):
        Expr.__init__(self,opIdent)
        self.name = name

    def __repr__(self):
        return "(ident %s)" % self.name

    def __str__(self):
        return self.name

class CallExpr(Expr):
    def __init__(self,funcname,params):
        Expr.__init__(self,opCall)
        self.funcname = funcname
        self.params   = params

    def __repr__(self):
        result = "(call %s [" % self.funcname
        comma  = ""
        for param in self.params:
            result += "%s%s" % (comma, repr(param))
            comma   = ","
        result += "])"
        return result

    def __str__(self):
        result = "%s(" % self.funcname
        comma = ""
        for param in self.params:
            result += "%s%s" % (comma, str(param))
            comma = ","

        result += ")"
        return result

class TestExpr(Expr):
    def __init__(self,cond,iftrue,iffalse):
        Expr.__init__(self,opTest)
        self.cond    = cond
        self.iftrue  = iftrue
        self.iffalse = iffalse

    def __repr__(self):
        return "(?: %s %s %s)" % (repr(self.cond),repr(self.iftrue),repr(self.iffalse))

    def __str__(self):
        return "(%s) ? (%s) : (%s)" % (self.cond, self.iftrue, self.iffalse)

class SingleArgExpr(Expr):
    def __init__(self,op,arg):
        Expr.__init__(self,op)
        self.arg = arg

    def __repr__(self):
        return "(%s %s)" % (self.op, repr(self.arg))

class DefinedExpr(SingleArgExpr):
    def __init__(self,op,macroname):
        SingleArgExpr.__init__(self.opDefined,macroname)

    def __str__(self):
        return "defined(%s)" % self.arg


class UnaryExpr(SingleArgExpr):
    def __init__(self,op,arg,opstr=None):
        SingleArgExpr.__init__(self,op,arg)
        if not opstr:
            opstr = op
        self.opstr = opstr

    def __str__(self):
        arg_s     = str(self.arg)
        arg_prec  = self.arg.precedence()
        self_prec = self.precedence()
        if arg_prec < self_prec:
            return "%s(%s)" % (self.opstr,arg_s)
        else:
            return "%s%s" % (self.opstr, arg_s)

class TwoArgExpr(Expr):
    def __init__(self,op,arg1,arg2):
        Expr.__init__(self,op)
        self.arg1 = arg1
        self.arg2 = arg2

    def __repr__(self):
        return "(%s %s %s)" % (self.op, repr(self.arg1), repr(self.arg2))

class BinaryExpr(TwoArgExpr):
    def __init__(self,op,arg1,arg2,opstr=None):
        TwoArgExpr.__init__(self,op,arg1,arg2)
        if not opstr:
            opstr = op
        self.opstr = opstr

    def __str__(self):
        arg1_s    = str(self.arg1)
        arg2_s    = str(self.arg2)
        arg1_prec = self.arg1.precedence()
        arg2_prec = self.arg2.precedence()
        self_prec = self.precedence()

        result = ""
        if arg1_prec < self_prec:
            result += "(%s)" % arg1_s
        else:
            result += arg1_s

        result += " %s " % self.opstr

        if arg2_prec < self_prec:
            result += "(%s)" % arg2_s
        else:
            result += arg2_s

        return result

#####################################################################################
#####################################################################################
#####                                                                           #####
#####           C P P   E X P R E S S I O N   P A R S E R                       #####
#####                                                                           #####
#####################################################################################
#####################################################################################


class ExprParser:
    """a class used to convert a list of tokens into a cpp Expr object"""

    re_octal   = re.compile(r"\s*\(0[0-7]+\).*")
    re_decimal = re.compile(r"\s*\(\d+[ulUL]*\).*")
    re_hexadecimal = re.compile(r"\s*\(0[xX][0-9a-fA-F]*\).*")

    def __init__(self,tokens):
        self.tok = tokens
        self.n   = len(self.tok)
        self.i   = 0

    def mark(self):
        return self.i

    def release(self,pos):
        self.i = pos

    def peekId(self):
        if self.i < self.n:
            return self.tok[self.i].id
        return None

    def peek(self):
        if self.i < self.n:
            return self.tok[self.i]
        return None

    def skip(self):
        if self.i < self.n:
            self.i += 1

    def skipOptional(self,id):
        if self.i < self.n and self.tok[self.i].id == id:
            self.i += 1

    def skipSpaces(self):
        i   = self.i
        n   = self.n
        tok = self.tok
        while i < n and (tok[i] == tokSPACE or tok[i] == tokLN):
            i += 1
        self.i = i

    # all the isXXX functions returns a (expr,nextpos) pair if a match is found
    # or None if not

    def is_integer(self):
        id = self.tok[self.i].id
        c  = id[0]
        if c < '0' or c > '9':
            return None

        m = ExprParser.re_octal.match(id)
        if m:
            return (IntExpr(id), m.end(1))

        m = ExprParser.re_decimal.match(id)
        if m:
            return (IntExpr(id), m.end(1))

        m = ExprParser.re_hexadecimal(id)
        if m:
            return (IntExpr(id), m.end(1))

        return None

    def is_defined(self):
        id = self.tok[self.i].id
        if id != "defined":
            return None

        pos = self.mark()

        use_paren = 0
        if self.peekId() == tokLPAREN:
            self.skip()
            use_paren = 1

        if self.peekId() != tokIDENT:
            self.throw( BadExpectedToken, "identifier expected")

        macroname = self.peek().value
        self.skip()
        if use_paren:
            self.skipSpaces()
            if self.peekId() != tokRPAREN:
                self.throw( BadExpectedToken, "missing right-paren after 'defined' directive")
            self.skip()

        i = self.i
        return (DefinedExpr(macroname),i+1)

    def is_call_or_ident(self):
        pass

    def parse(self, i):
        return None

#####################################################################################
#####################################################################################
#####                                                                           #####
#####           C P P   E X P R E S S I O N S                                   #####
#####                                                                           #####
#####################################################################################
#####################################################################################

class CppInvalidExpression(Exception):
    """an exception raised when an invalid/unsupported cpp expression is detected"""
    pass

class CppExpr:
    """a class that models the condition of #if directives into
        an expression tree. each node in the tree is of the form (op,arg) or (op,arg1,arg2)
        where "op" is a string describing the operation"""

    unaries  = [ "!", "~" ]
    binaries = [ "+", "-", "<", "<=", ">=", ">", "&&", "||", "*", "/", "%", "&", "|", "^", "<<", ">>", "==", "!=" ]
    precedences = { "||": 1,
                    "&&": 2,
                     "|": 3,
                     "^": 4,
                     "&": 5,
                     "==":6, "!=":6,
                     "<":7, "<=":7, ">":7, ">=":7,
                     "<<":8, ">>":8,
                     "+":9, "-":9,
                     "*":10, "/":10, "%":10,
                     "!":11, "~":12
                     }

    def __init__(self, tokens):
        """initialize a CppExpr. 'tokens' must be a CppToken list"""
        self.tok  = tokens
        self.n    = len(tokens)
        if debugCppExpr:
            print "CppExpr: trying to parse %s" % repr(tokens)
        expr      = self.is_expr(0)
        if debugCppExpr:
            print "CppExpr: got " + repr(expr)
        self.expr = expr[0]

    re_cpp_constant = re.compile(r"((\d|\w|_)+)")

    def throw(self,exception,i,msg):
        if i < self.n:
            tok = self.tok[i]
            print "%d:%d: %s" % (tok.lineno,tok.colno,msg)
        else:
            print "EOF: %s" % msg
        raise exception

    def skip_spaces(self,i):
        """skip spaces in input token list"""
        while i < self.n:
            t = self.tok[i]
            if t.id != tokSPACE and t.id != tokLN:
                break
            i += 1
        return i

    def expectId(self,i,id):
        """check that a given token id is at the current position, then skip over it"""
        i = self.skip_spaces(i)
        if i >= self.n or self.tok[i].id != id:
            self.throw(BadExpectedToken,i,"### expecting '%s' in expression, got '%s'" % (id, self.tok[i].id))
        return i+1

    def expectIdent(self,i):
        i = self.skip_spaces(i)
        if i >= self.n or self.tok[i].id != tokIDENT:
            self.throw(BadExpectedToken,i,"### expecting identifier in expression, got '%s'" % (id, self.tok[i].id))
        return i+1

    # the is_xxxxx function returns either None or a pair (e,nextpos)
    # where 'e' is an expression tuple (e.g. (op,arg)) and 'nextpos' is
    # the corresponding next position in the input token list
    #

    def is_decimal(self,i):
        v = self.tok[i].value[:]
        while len(v) > 0 and v[-1] in "ULul":
            v = v[:-1]
        for digit in v:
            if not digit.isdigit():
                return None

        # for an integer expression tuple, the argument
        # is simply the value as an integer
        val = string.atoi(v)
        return ("int", val), i+1

    def is_hexadecimal(self,i):
        v = self.tok[i].value[:]
        while len(v) > 0 and v[-1] in "ULul":
            v = v[:-1]
        if len(v) > 2 and (v[0:2] == "0x" or v[0:2] == "0X"):
            for digit in v[2:]:
                if not digit in "0123456789abcdefABCDEF":
                    return None

            # for an hex expression tuple, the argument
            # is the value as an integer
            val = int(v[2:], 16)
            return ("hex", val), i+1

        return None

    def is_integer(self,i):
        if self.tok[i].id != tokNUMBER:
            return None

        c = self.is_decimal(i)
        if c: return c

        c = self.is_hexadecimal(i)
        if c: return c

        return None

    def is_number(self,i):
        t = self.tok[i]
        if t.id == tokMINUS and i+1 < self.n:
            c = self.is_integer(i+1)
            if c:
                e, i2 = c
                op, val  = e
                return (op, -val), i2
        if t.id == tokPLUS and i+1 < self.n:
            c = self.is_integer(i+1)
            if c: return c

        return self.is_integer(i)


    def is_alnum(self,i):
        """test wether a given token is alpha-numeric"""
        i = self.skip_spaces(i)
        if i >= self.n:
            return None
        t = self.tok[i]
        m = CppExpr.re_cpp_constant.match(t.id)
        if m:
            #print "... alnum '%s'" % m.group(1)
            r = m.group(1)
            return ("ident", r), i+1
        return None

    def is_defined(self,i):
        t = self.tok[i]
        if t.id != tokDEFINED:
            return None

        # we have the defined keyword, check the rest
        i = self.skip_spaces(i+1)
        use_parens = 0
        if i < self.n and self.tok[i].id == tokLPAREN:
            use_parens = 1
            i = self.skip_spaces(i+1)

        if i >= self.n:
            self.throw(CppConstantExpected,i,"### 'defined' must be followed  by macro name or left paren")

        t = self.tok[i]
        if t.id != tokIDENT:
            self.throw(CppConstantExpected,i,"### 'defined' must be followed by macro name")

        i += 1
        if use_parens:
            i = self.expectId(i,tokRPAREN)

        return ("defined",t.value), i


    def is_call_or_ident(self,i):
        i = self.skip_spaces(i)
        if i >= self.n:
            return None

        t = self.tok[i]
        if t.id != tokIDENT:
            return None

        name = t.value

        i = self.skip_spaces(i+1)
        if i >= self.n or self.tok[i].id != tokLPAREN:
            return ("ident", name), i

        params    = []
        depth     = 1
        i += 1
        j  = i
        while i < self.n:
            id = self.tok[i].id
            if id == tokLPAREN:
                depth += 1
            elif depth == 1 and (id == tokCOMMA or id == tokRPAREN):
                while j < i and self.tok[j].id == tokSPACE:
                    j += 1
                k = i
                while k > j and self.tok[k-1].id == tokSPACE:
                    k -= 1
                param = self.tok[j:k]
                params.append( param )
                if id == tokRPAREN:
                    break
                j = i+1
            elif id == tokRPAREN:
                depth -= 1
            i += 1

        if i >= self.n:
            return None

        return ("call", (name, params)), i+1

    def is_token(self,i,token):
        i = self.skip_spaces(i)
        if i >= self.n or self.tok[i].id != token:
            return None
        return token, i+1


    def is_value(self,i):
        t = self.tok[i]
        if t.id == tokSTRING:
            return ("string", t.value), i+1

        c = self.is_number(i)
        if c: return c

        c = self.is_defined(i)
        if c: return c

        c = self.is_call_or_ident(i)
        if c: return c

        i = self.skip_spaces(i)
        if i >= self.n or self.tok[i].id != tokLPAREN:
            return None

        popcount = 1
        i2       = i+1
        while i2 < self.n:
            t = self.tok[i2]
            if t.id == tokLPAREN:
                popcount += 1
            elif t.id == tokRPAREN:
                popcount -= 1
                if popcount == 0:
                    break
            i2 += 1

        if popcount != 0:
            self.throw(CppInvalidExpression, i, "expression missing closing parenthesis")

        if debugCppExpr:
            print "CppExpr: trying to parse sub-expression %s" % repr(self.tok[i+1:i2])
        oldcount   = self.n
        self.n     = i2
        c          = self.is_expr(i+1)
        self.n     = oldcount
        if not c:
            self.throw(CppInvalidExpression, i, "invalid expression within parenthesis")

        e, i = c
        return e, i2+1

    def is_unary(self,i):
        i = self.skip_spaces(i)
        if i >= self.n:
            return None

        t = self.tok[i]
        if t.id in CppExpr.unaries:
            c = self.is_unary(i+1)
            if not c:
                self.throw(CppInvalidExpression, i, "%s operator must be followed by value" % t.id)
            e, i = c
            return (t.id, e), i

        return self.is_value(i)

    def is_binary(self,i):
        i = self.skip_spaces(i)
        if i >= self.n:
            return None

        c = self.is_unary(i)
        if not c:
            return None

        e1, i2 = c
        i2 = self.skip_spaces(i2)
        if i2 >= self.n:
            return c

        t = self.tok[i2]
        if t.id in CppExpr.binaries:
            c = self.is_binary(i2+1)
            if not c:
                self.throw(CppInvalidExpression, i,"### %s operator must be followed by value" % t.id )
            e2, i3 = c
            return (t.id, e1, e2), i3

        return None

    def is_expr(self,i):
        return self.is_binary(i)

    def dump_node(self,e):
        op = e[0]
        line = "(" + op
        if op == "int":
            line += " %d)" % e[1]
        elif op == "hex":
            line += " 0x%x)" % e[1]
        elif op == "ident":
            line += " %s)" % e[1]
        elif op == "defined":
            line += " %s)" % e[1]
        elif op == "call":
            arg = e[1]
            line += " %s [" % arg[0]
            prefix = ""
            for param in arg[1]:
                par = ""
                for tok in param:
                    par += str(tok)
                line += "%s%s" % (prefix, par)
                prefix = ","
            line += "])"
        elif op in CppExpr.unaries:
            line += " %s)" % self.dump_node(e[1])
        elif op in CppExpr.binaries:
            line += " %s %s)" % (self.dump_node(e[1]), self.dump_node(e[2]))
        else:
            line += " ?%s)" % repr(e[1])

        return line

    def __repr__(self):
        return self.dump_node(self.expr)

    def source_node(self,e):
        op = e[0]
        if op == "int":
            return "%d" % e[1]
        if op == "hex":
            return "0x%x" % e[1]
        if op == "ident":
            # XXX: should try to expand
            return e[1]
        if op == "defined":
            return "defined(%s)" % e[1]

        prec = CppExpr.precedences.get(op,1000)
        arg  = e[1]
        if op in CppExpr.unaries:
            arg_src = self.source_node(arg)
            arg_op  = arg[0]
            arg_prec = CppExpr.precedences.get(arg[0],1000)
            if arg_prec < prec:
                return "!(" + arg_src + ")"
            else:
                return "!" + arg_src
        if op in CppExpr.binaries:
            arg2     = e[2]
            arg1_op  = arg[0]
            arg2_op  = arg2[0]
            arg1_src = self.source_node(arg)
            arg2_src = self.source_node(arg2)
            if CppExpr.precedences.get(arg1_op,1000) < prec:
                arg1_src = "(%s)" % arg1_src
            if CppExpr.precedences.get(arg2_op,1000) < prec:
                arg2_src = "(%s)" % arg2_src

            return "%s %s %s" % (arg1_src, op, arg2_src)
        return "???"

    def __str__(self):
        return self.source_node(self.expr)

    def int_node(self,e):
        if e[0] == "int":
            return e[1]
        elif e[1] == "hex":
            return int(e[1],16)
        else:
            return None

    def toInt(self):
        return self.int_node(self.expr)

    def optimize_node(self,e,macros={}):
        op = e[0]
        if op == "defined":
            name = e[1]
            if macros.has_key(name):
                if macros[name] == kCppUndefinedMacro:
                    return ("int", 0)
                else:
                    return ("int", 1)

            if kernel_remove_config_macros and name.startswith("CONFIG_"):
                return ("int", 0)

        elif op == "!":
            op, v = e
            v = self.optimize_node(v, macros)
            if v[0] == "int":
                if v[1] == 0:
                    return ("int", 1)
                else:
                    return ("int", 0)

        elif op == "&&":
            op, l, r = e
            l  = self.optimize_node(l, macros)
            r  = self.optimize_node(r, macros)
            li = self.int_node(l)
            ri = self.int_node(r)
            if li != None:
                if li == 0:
                    return ("int", 0)
                else:
                    return r

        elif op == "||":
            op, l, r = e
            l  = self.optimize_node(l, macros)
            r  = self.optimize_node(r, macros)
            li = self.int_node(l)
            ri = self.int_node(r)
            if li != None:
                if li == 0:
                    return r
                else:
                    return ("int", 1)
            elif ri != None:
                if ri == 0:
                    return l
                else:
                    return ("int", 1)
        return e

    def optimize(self,macros={}):
        self.expr = self.optimize_node(self.expr,macros)

    def removePrefixedNode(self,e,prefix,names):
        op = e[0]
        if op == "defined":
            name = e[1]
            if name.startswith(prefix):
                if names.has_key[name] and names[name] == "y":
                    return ("int", 1)
                else:
                    return ("int", 0)

        elif op in CppExpr.unaries:
            op, v = e
            v = self.removePrefixedNode(v,prefix,names)
            return (op, v)
        elif op in CppExpr.binaries:
            op, v1, v2 = e
            v1 = self.removePrefixedNode(v1,prefix,names)
            v2 = self.removePrefixedNode(v2,prefix,names)
            return (op, v1, v2)
        elif op == "call":
            func, params = e[1]
            params2 = []
            for param in params:
                params2.append( self.removePrefixedNode(param,prefix,names) )
            return (op, (func, params2))

        return e

    def removePrefixed(self,prefix,names={}):
        self.expr = self.removePrefixedNode(self.expr,prefix,names)

    def is_equal_node(self,e1,e2):
        if e1[0] != e2[0] or len(e1) != len(e2):
            return False

        op = e1[0]
        if op == "int" or op == "hex" or op == "!" or op == "defined":
            return e1[0] == e2[0]

        return self.is_equal_node(e1[1],e2[1]) and self.is_equal_node(e1[2],e2[2])

    def is_equal(self,other):
        return self.is_equal_node(self.expr,other.expr)

def test_cpp_expr(expr, expected):
    e = CppExpr( CppLineTokenizer( expr ).toTokenList() )
    #print repr(e.expr)
    s1 = repr(e)
    if s1 != expected:
        print "KO: expression '%s' generates '%s', should be '%s'" % (expr, s1, expected)
    else:
        #print "OK: expression '%s'" % expr
        pass

def test_cpp_expr_optim(expr, expected, macros={}):
    e = CppExpr( CppLineTokenizer( expr ).toTokenList() )
    e.optimize(macros)

    s1 = repr(e)
    if s1 != expected:
        print "KO: optimized expression '%s' generates '%s', should be '%s'" % (expr, s1, expected)
    else:
        #print "OK: optmized expression '%s'" % expr
        pass

def test_cpp_expr_source(expr, expected):
    e = CppExpr( CppLineTokenizer( expr ).toTokenList() )
    s1 = str(e)
    if s1 != expected:
        print "KO: source expression '%s' generates '%s', should be '%s'" % (expr, s1, expected)
    else:
        #print "OK: source expression '%s'" % expr
        pass

def test_CppExpr():
    print "testing CppExpr"
    test_cpp_expr( "0", "(int 0)" )
    test_cpp_expr( "1", "(int 1)" )
    test_cpp_expr( "1 && 1", "(&& (int 1) (int 1))" )
    test_cpp_expr( "1 && 0", "(&& (int 1) (int 0))" )
    test_cpp_expr( "EXAMPLE", "(ident EXAMPLE)" )
    test_cpp_expr( "EXAMPLE - 3", "(- (ident EXAMPLE) (int 3))" )
    test_cpp_expr( "defined(EXAMPLE)", "(defined EXAMPLE)" )
    test_cpp_expr( "!defined(EXAMPLE)", "(! (defined EXAMPLE))" )
    test_cpp_expr( "defined(ABC) || defined(BINGO)", "(|| (defined ABC) (defined BINGO))" )
    test_cpp_expr( "FOO(BAR)", "(call FOO [BAR])" )

    test_cpp_expr_optim( "0", "(int 0)" )
    test_cpp_expr_optim( "1", "(int 1)" )
    test_cpp_expr_optim( "1 && 1", "(int 1)" )
    test_cpp_expr_optim( "1 && 0", "(int 0)" )
    test_cpp_expr_optim( "0 && 1", "(int 0)" )
    test_cpp_expr_optim( "0 && 0", "(int 0)" )
    test_cpp_expr_optim( "1 || 1", "(int 1)" )
    test_cpp_expr_optim( "1 || 0", "(int 1)" )
    test_cpp_expr_optim( "0 || 1", "(int 1)" )
    test_cpp_expr_optim( "0 || 0", "(int 0)" )
    test_cpp_expr_optim( "EXAMPLE", "(ident EXAMPLE)" )
    test_cpp_expr_optim( "EXAMPLE - 3", "(- (ident EXAMPLE) (int 3))" )
    test_cpp_expr_optim( "defined(EXAMPLE)", "(defined EXAMPLE)" )
    test_cpp_expr_optim( "defined(EXAMPLE)", "(int 1)", { "EXAMPLE": "XOWOE" } )
    test_cpp_expr_optim( "defined(EXAMPLE)", "(int 0)", { "EXAMPLE": kCppUndefinedMacro} )
    test_cpp_expr_optim( "!defined(EXAMPLE)", "(! (defined EXAMPLE))" )
    test_cpp_expr_optim( "!defined(EXAMPLE)", "(int 0)", { "EXAMPLE" : "XOWOE" } )
    test_cpp_expr_optim( "!defined(EXAMPLE)", "(int 1)", { "EXAMPLE" : kCppUndefinedMacro } )
    test_cpp_expr_optim( "defined(ABC) || defined(BINGO)", "(|| (defined ABC) (defined BINGO))" )
    test_cpp_expr_optim( "defined(ABC) || defined(BINGO)", "(int 1)", { "ABC" : "1" } )
    test_cpp_expr_optim( "defined(ABC) || defined(BINGO)", "(int 1)", { "BINGO" : "1" } )
    test_cpp_expr_optim( "defined(ABC) || defined(BINGO)", "(defined ABC)", { "BINGO" : kCppUndefinedMacro } )
    test_cpp_expr_optim( "defined(ABC) || defined(BINGO)", "(int 0)", { "ABC" : kCppUndefinedMacro, "BINGO" : kCppUndefinedMacro } )

    test_cpp_expr_source( "0", "0" )
    test_cpp_expr_source( "1", "1" )
    test_cpp_expr_source( "1 && 1", "1 && 1" )
    test_cpp_expr_source( "1 && 0", "1 && 0" )
    test_cpp_expr_source( "0 && 1", "0 && 1" )
    test_cpp_expr_source( "0 && 0", "0 && 0" )
    test_cpp_expr_source( "1 || 1", "1 || 1" )
    test_cpp_expr_source( "1 || 0", "1 || 0" )
    test_cpp_expr_source( "0 || 1", "0 || 1" )
    test_cpp_expr_source( "0 || 0", "0 || 0" )
    test_cpp_expr_source( "EXAMPLE", "EXAMPLE" )
    test_cpp_expr_source( "EXAMPLE - 3", "EXAMPLE - 3" )
    test_cpp_expr_source( "defined(EXAMPLE)", "defined(EXAMPLE)" )
    test_cpp_expr_source( "defined EXAMPLE", "defined(EXAMPLE)" )


#####################################################################################
#####################################################################################
#####                                                                           #####
#####          C P P   B L O C K                                                #####
#####                                                                           #####
#####################################################################################
#####################################################################################

class Block:
    """a class used to model a block of input source text. there are two block types:
        - direcive blocks: contain the tokens of a single pre-processor directive (e.g. #if)
        - text blocks, contain the tokens of non-directive blocks

       the cpp parser class below will transform an input source file into a list of Block
       objects (grouped in a BlockList object for convenience)"""

    def __init__(self,tokens,directive=None,lineno=0):
        """initialize a new block, if 'directive' is None, this is a text block
           NOTE: this automatically converts '#ifdef MACRO' into '#if defined(MACRO)'
                 and '#ifndef MACRO' into '#if !defined(MACRO)'"""
        if directive == "ifdef":
            tok = Token()
            tok.set(tokDEFINED)
            tokens = [ tok ] + tokens
            directive = "if"

        elif directive == "ifndef":
            tok1 = Token()
            tok2 = Token()
            tok1.set(tokNOT)
            tok2.set(tokDEFINED)
            tokens = [ tok1, tok2 ] + tokens
            directive = "if"

        self.tokens    = tokens
        self.directive = directive
        if lineno > 0:
            self.lineno = lineno
        else:
            self.lineno = self.tokens[0].lineno

        if self.isIf():
            self.expr = CppExpr( self.tokens )

    def isDirective(self):
        """returns True iff this is a directive block"""
        return self.directive != None

    def isConditional(self):
        """returns True iff this is a conditional directive block"""
        return self.directive in ["if","ifdef","ifndef","else","elif","endif"]

    def isDefine(self):
        """returns the macro name in a #define directive, or None otherwise"""
        if self.directive != "define":
            return None

        return self.tokens[0].value

    def isIf(self):
        """returns True iff this is an #if-like directive block"""
        return self.directive in ["if","ifdef","ifndef","elif"]

    def isInclude(self):
        """checks wether this is a #include directive. if true, then returns the
           corresponding file name (with brackets or double-qoutes). None otherwise"""
        if self.directive != "include":
            return None

        #print "iii " + repr(self.tokens)
        if self.tokens[0].id == tokSTRING:
            # a double-quote include, that's easy
            return self.tokens[0].value

        # we only want the bracket part, not any comments or junk after it
        if self.tokens[0].id == "<":
            i   = 0
            tok = self.tokens
            n   = len(tok)
            while i < n and tok[i].id != ">":
                i += 1

            if i >= n:
                return None

            return string.join([ str(x) for x in tok[:i+1] ],"")

        else:
            return None

    def __repr__(self):
        """generate the representation of a given block"""
        if self.directive:
            result = "#%s " % self.directive
            if self.isIf():
                result += repr(self.expr)
            else:
                for tok in self.tokens:
                    result += repr(tok)
        else:
            result = ""
            for tok in self.tokens:
                result += repr(tok)

        return result

    def __str__(self):
        """generate the string representation of a given block"""
        if self.directive:
            if self.directive == "if":
                # small optimization to re-generate #ifdef and #ifndef
                e = self.expr.expr
                op = e[0]
                if op == "defined":
                    result = "#ifdef %s" % e[1]
                elif op == "!" and e[1][0] == "defined":
                    result = "#ifndef %s" % e[1][1]
                else:
                    result = "#if " + str(self.expr)
            else:
                result = "#%s" % self.directive
                if len(self.tokens):
                    result += " "
                for tok in self.tokens:
                    result += str(tok)
        else:
            result = ""
            for tok in self.tokens:
                result += str(tok)

        return result


class BlockList:
    """a convenience class used to hold and process a list of blocks returned by
       the cpp parser"""
    def __init__(self,blocks):
        self.blocks = blocks

    def __len__(self):
        return len(self.blocks)

    def __getitem__(self,n):
        return self.blocks[n]

    def __repr__(self):
        return repr(self.blocks)

    def __str__(self):
        result = ""
        for b in self.blocks:
            result += str(b)
            if b.isDirective():
                result += '\n'
        return result

    def  optimizeIf01(self):
        """remove the code between #if 0 .. #endif in a BlockList"""
        self.blocks = optimize_if01(self.blocks)

    def optimizeMacros(self, macros):
        """remove known defined and undefined macros from a BlockList"""
        for b in self.blocks:
            if b.isIf():
                b.expr.optimize(macros)

    def removeMacroDefines(self,macros):
        """remove known macro definitions from a BlockList"""
        self.blocks = remove_macro_defines(self.blocks,macros)

    def removePrefixed(self,prefix,names):
        for b in self.blocks:
            if b.isIf():
                b.expr.removePrefixed(prefix,names)

    def optimizeAll(self,macros):
        self.optimizeMacros(macros)
        self.optimizeIf01()
        return

    def findIncludes(self):
        """return the list of included files in a BlockList"""
        result = []
        for b in self.blocks:
            i = b.isInclude()
            if i:
                result.append(i)

        return result


    def write(self,out):
        out.write(str(self))

    def removeComments(self):
        for b in self.blocks:
            for tok in b.tokens:
                if tok.id == tokSPACE:
                    tok.value = " "

    def removeEmptyLines(self):
        # state = 1 => previous line was tokLN
        # state = 0 => previous line was directive
        state  = 1
        for b in self.blocks:
            if b.isDirective():
                #print "$$$ directive %s" % str(b)
                state = 0
            else:
                # a tokLN followed by spaces is replaced by a single tokLN
                # several successive tokLN are replaced by a single one
                #
                dst   = []
                src   = b.tokens
                n     = len(src)
                i     = 0
                #print "$$$ parsing %s" % repr(src)
                while i < n:
                    # find final tokLN
                    j = i
                    while j < n and src[j].id != tokLN:
                        j += 1

                    if j >= n:
                        # uhhh
                        dst += src[i:]
                        break

                    if src[i].id == tokSPACE:
                        k = i+1
                        while src[k].id == tokSPACE:
                            k += 1

                        if k == j: # empty lines with spaces in it
                            i = j  # remove the spaces

                    if i == j:
                        # an empty line
                        if state == 1:
                            i += 1   # remove it
                        else:
                            state = 1
                            dst.append(src[i])
                            i   += 1
                    else:
                        # this line is not empty, remove trailing spaces
                        k = j
                        while k > i and src[k-1].id == tokSPACE:
                            k -= 1

                        nn = i
                        while nn < k:
                            dst.append(src[nn])
                            nn += 1
                        dst.append(src[j])
                        state = 0
                        i = j+1

                b.tokens = dst

    def removeVarsAndFuncs(self,knownStatics=set()):
        """remove all extern and static declarations corresponding
           to variable and function declarations. we only accept typedefs
           and enum/structs/union declarations.

           however, we keep the definitions corresponding to the set
           of known static inline functions in the set 'knownStatics',
           which is useful for optimized byteorder swap functions and
           stuff like that.
           """
        # state = 1 => typedef/struct encountered
        # state = 2 => vars or func declaration encountered, skipping until ";"
        # state = 0 => normal (i.e. LN + spaces)
        state      = 0
        depth      = 0
        blocks2    = []
        for b in self.blocks:
            if b.isDirective():
                blocks2.append(b)
            else:
                n     = len(b.tokens)
                i     = 0
                first = 0
                if state == 2:
                    first = n
                while i < n:
                    tok = b.tokens[i]
                    if state == 0:
                        bad = 0
                        if tok.id in [tokLN, tokSPACE]:
                            pass
                        elif tok.value in [ 'struct', 'typedef', 'enum', 'union', '__extension__' ]:
                            state = 1
                        else:
                            if tok.value in [ 'static', 'extern', '__KINLINE' ]:
                                j = i+1
                                ident = ""
                                while j < n and not (b.tokens[j].id in [ '(', ';' ]):
                                    if b.tokens[j].id == tokIDENT:
                                        ident = b.tokens[j].value
                                    j += 1
                                if j < n and ident in knownStatics:
                                    # this is a known static, we're going to keep its
                                    # definition in the final output
                                    state = 1
                                else:
                                    #print "### skip static '%s'" % ident
                                    pass

                            if state == 0:
                                if i > first:
                                    #print "### intermediate from '%s': '%s'" % (tok.value, repr(b.tokens[first:i]))
                                    blocks2.append( Block(b.tokens[first:i]) )
                                state = 2
                                first = n

                    else:  # state > 0
                        if tok.id == '{':
                            depth += 1

                        elif tok.id == '}':
                            if depth > 0:
                                depth -= 1

                        elif depth == 0 and tok.id == ';':
                            if state == 2:
                                first = i+1
                            state = 0

                    i += 1

                if i > first:
                    #print "### final '%s'" % repr(b.tokens[first:i])
                    blocks2.append( Block(b.tokens[first:i]) )

        self.blocks = blocks2

    def insertDisclaimer(self,disclaimer="/* auto-generated file, DO NOT EDIT */"):
        """insert your standard issue disclaimer that this is an
           auto-generated file, etc.."""
        tokens = CppLineTokenizer( disclaimer ).toTokenList()
        tokens = tokens[:-1]  # remove trailing tokLN
        self.blocks = [ Block(tokens) ] + self.blocks

class BlockParser:
    """a class used to convert an input source file into a BlockList object"""

    def __init__(self,tokzer=None):
        """initialize a block parser. the input source is provided through a Tokenizer
           object"""
        self.reset(tokzer)

    def reset(self,tokzer):
        self.state  = 1
        self.tokzer = tokzer

    def getBlocks(self,tokzer=None):
        """tokenize and parse the input source, return a BlockList object
           NOTE: empty and line-numbering directives are ignored and removed
                 from the result. as a consequence, it is possible to have
                 two successive text blocks in the result"""
        # state 0 => in source code
        # state 1 => in source code, after a LN
        # state 2 => in source code, after LN then some space
        state   = 1
        lastLN  = 0
        current = []
        blocks  = []

        if tokzer == None:
            tokzer = self.tokzer

        while 1:
            tok = tokzer.getToken()
            if tok.id == tokEOF:
                break

            if tok.id == tokLN:
                state    = 1
                current.append(tok)
                lastLN   = len(current)

            elif tok.id == tokSPACE:
                if state == 1:
                    state = 2
                current.append(tok)

            elif tok.id == "#":
                if state > 0:
                    # this is the start of a directive

                    if lastLN > 0:
                        # record previous tokens as text block
                        block   = Block(current[:lastLN])
                        blocks.append(block)
                        lastLN  = 0

                    current = []

                    # skip spaces after the #
                    while 1:
                        tok = tokzer.getToken()
                        if tok.id != tokSPACE:
                            break

                    if tok.id != tokIDENT:
                        # empty or line-numbering, ignore it
                        if tok.id != tokLN and tok.id != tokEOF:
                            while 1:
                                tok = tokzer.getToken()
                                if tok.id == tokLN or tok.id == tokEOF:
                                    break
                        continue

                    directive = tok.value
                    lineno    = tok.lineno

                    # skip spaces
                    tok = tokzer.getToken()
                    while tok.id == tokSPACE:
                        tok = tokzer.getToken()

                    # then record tokens until LN
                    dirtokens = []
                    while tok.id != tokLN and tok.id != tokEOF:
                        dirtokens.append(tok)
                        tok = tokzer.getToken()

                    block = Block(dirtokens,directive,lineno)
                    blocks.append(block)
                    state   = 1

            else:
                state = 0
                current.append(tok)

        if len(current) > 0:
            block = Block(current)
            blocks.append(block)

        return BlockList(blocks)

    def parse(self,tokzer):
        return self.getBlocks( tokzer )

    def parseLines(self,lines):
        """parse a list of text lines into a BlockList object"""
        return self.getBlocks( CppLinesTokenizer(lines) )

    def parseFile(self,path):
        """parse a file into a BlockList object"""
        file = open(path, "rt")
        result = self.getBlocks( CppFileTokenizer(file) )
        file.close()
        return result


def test_block_parsing(lines,expected):
    blocks = BlockParser().parse( CppLinesTokenizer(lines) )
    if len(blocks) != len(expected):
        raise BadExpectedToken, "parser.buildBlocks returned '%s' expecting '%s'" \
              % (str(blocks), repr(expected))
    for n in range(len(blocks)):
        if str(blocks[n]) != expected[n]:
            raise BadExpectedToken, "parser.buildBlocks()[%d] is '%s', expecting '%s'" \
                  % (n, str(blocks[n]), expected[n])
    #for block in blocks:
    #    print block

def test_BlockParser():
    test_block_parsing(["#error hello"],["#error hello"])
    test_block_parsing([ "foo", "", "bar" ], [ "foo\n\nbar\n" ])
    test_block_parsing([ "foo", "  #  ", "bar" ], [ "foo\n","bar\n" ])
    test_block_parsing(\
        [ "foo", "   #  ", "  #  /* ahah */ if defined(__KERNEL__) ", "bar", "#endif" ],
        [ "foo\n", "#ifdef __KERNEL__", "bar\n", "#endif" ] )


#####################################################################################
#####################################################################################
#####                                                                           #####
#####        B L O C K   L I S T   O P T I M I Z A T I O N                      #####
#####                                                                           #####
#####################################################################################
#####################################################################################

def  remove_macro_defines( blocks, excludedMacros=set() ):
    """remove macro definitions like #define <macroName>  ...."""
    result = []
    for b in blocks:
        macroName = b.isDefine()
        if macroName == None or not macroName in excludedMacros:
            result.append(b)

    return result

def  find_matching_endif( blocks, i ):
    n     = len(blocks)
    depth = 1
    while i < n:
        if blocks[i].isDirective():
            dir = blocks[i].directive
            if dir in [ "if", "ifndef", "ifdef" ]:
                depth += 1
            elif depth == 1 and dir in [ "else", "elif" ]:
                return i
            elif dir == "endif":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return i

def  optimize_if01( blocks ):
    """remove the code between #if 0 .. #endif in a list of CppBlocks"""
    i = 0
    n = len(blocks)
    result = []
    while i < n:
        j = i
        while j < n and not blocks[j].isIf():
            j += 1
        if j > i:
            D2("appending lines %d to %d" % (blocks[i].lineno, blocks[j-1].lineno))
            result += blocks[i:j]
        if j >= n:
            break
        expr = blocks[j].expr
        r    = expr.toInt()
        if r == None:
            result.append(blocks[j])
            i = j + 1
            continue

        if r == 0:
            # if 0 => skip everything until the corresponding #endif
            j = find_matching_endif( blocks, j+1 )
            if j >= n:
                # unterminated #if 0, finish here
                break
            dir = blocks[j].directive
            if dir == "endif":
                D2("remove 'if 0' .. 'endif' (lines %d to %d)" % (blocks[i].lineno, blocks[j].lineno))
                i = j + 1
            elif dir == "else":
                # convert 'else' into 'if 1'
                D2("convert 'if 0' .. 'else' into 'if 1' (lines %d to %d)" % (blocks[i].lineno, blocks[j-1].lineno))
                blocks[j].directive = "if"
                blocks[j].expr      = CppExpr( CppLineTokenizer("1").toTokenList() )
                i = j
            elif dir == "elif":
                # convert 'elif' into 'if'
                D2("convert 'if 0' .. 'elif' into 'if'")
                blocks[j].directive = "if"
                i = j
            continue

        # if 1 => find corresponding endif and remove/transform them
        k = find_matching_endif( blocks, j+1 )
        if k >= n:
            # unterminated #if 1, finish here
            D2("unterminated 'if 1'")
            result += blocks[j+1:k]
            break

        dir = blocks[k].directive
        if dir == "endif":
            D2("convert 'if 1' .. 'endif' (lines %d to %d)"  % (blocks[j].lineno, blocks[k].lineno))
            result += optimize_if01(blocks[j+1:k])
            i       = k+1
        elif dir == "else":
            # convert 'else' into 'if 0'
            D2("convert 'if 1' .. 'else' (lines %d to %d)"  % (blocks[j].lineno, blocks[k].lineno))
            result += optimize_if01(blocks[j+1:k])
            blocks[k].directive = "if"
            blocks[k].expr      = CppExpr( CppLineTokenizer("0").toTokenList() )
            i = k
        elif dir == "elif":
            # convert 'elif' into 'if 0'
            D2("convert 'if 1' .. 'elif' (lines %d to %d)" % (blocks[j].lineno, blocks[k].lineno))
            result += optimize_if01(blocks[j+1:k])
            blocks[k].expr      = CppExpr( CppLineTokenizer("0").toTokenList() )
            i = k
    return result

def  test_optimizeAll():
    text = """\
#if 1
#define  GOOD_1
#endif
#if 0
#define  BAD_2
#define  BAD_3
#endif

#if 1
#define  GOOD_2
#else
#define  BAD_4
#endif

#if 0
#define  BAD_5
#else
#define  GOOD_3
#endif

#if 0
#if 1
#define  BAD_6
#endif
#endif\
"""

    expected = """\
#define GOOD_1

#define GOOD_2

#define GOOD_3

"""

    print "running test_BlockList.optimizeAll"
    out = StringOutput()
    lines = string.split(text, '\n')
    list = BlockParser().parse( CppLinesTokenizer(lines) )
    #D_setlevel(2)
    list.optimizeAll( {"__KERNEL__":kCppUndefinedMacro} )
    #print repr(list)
    list.write(out)
    if out.get() != expected:
        print "KO: macro optimization failed\n"
        print "<<<< expecting '",
        print expected,
        print "'\n>>>> result '"
        print out.get(),
        print "'\n----"


#####################################################################################
#####################################################################################
#####                                                                           #####
#####                                                                           #####
#####                                                                           #####
#####################################################################################
#####################################################################################

def runUnitTests():
    """run all unit tests for this program"""
    print "running unit tests"
    test_CppTokenizer()
    test_CppExpr()
    test_optimizeAll()
    test_BlockParser()
    print "OK"

if __name__ == "__main__":
    runUnitTests()
