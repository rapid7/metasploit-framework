import os
import sys
import argparse
import datetime

try:
    import glob
except ImportError:
    print("Please install glob package")
    sys.exit()

if sys.version_info[0] < 3:
    raise Exception("Must be using Python 3")

parser = argparse.ArgumentParser(description='This script identifies issues with module documentation, including missing documentation, and incorrect file names.  Output is in markdown format.',
    prefix_chars='--', )
parser.add_argument('-m', '--modules', type=str, default='auxiliary/scanner', help='Choose the modules category to work with. Respect the module category names as in metasploit-framework. Only one category should be passed, e.g. "auxiliary/admin", "exploits/android/browser" or "encoders" are valid entries.')
parser.add_argument('--show_all', action="store_true", default=False, help='Show the complete list of items. In default mode, modules with documentation are marked "[x]" and modules without are marked "[ ]". In issues mode, documentation files without module are marked "[ ]" and documentation files with module are marked "[x]".')
parser.add_argument('--show_issues', action="store_true", default=False, help='Show the list of documentation files without modules instead of modules withouth documentation file.')
parser.add_argument('-o', '--output', help="Writes to a file.")
args = parser.parse_args()

module_type = args.modules
show_all = args.show_all
show_issues = args.show_issues

modules = []
docs = []
path = os.path.abspath(os.path.join(os.path.realpath(__file__),"..","..",".."))

if os.path.exists(os.path.join(path, 'modules', module_type)):
    list_docs = glob.glob(os.path.join(path,'documentation/modules', module_type, '**/*.md'), recursive=True)
    list_modules = glob.glob(os.path.join(path, 'modules', module_type, '**/*.*'),recursive=True)
else:
    print("Path doesn't exist. Maybe you have passed a wrong module category or maybe there isn't any documentation file yet.")
    sys.exit()

for doc in list_docs:
    docs.append(doc.split('.')[0].replace('/documentation/','/'))
for module in list_modules:
    modules.append(module.split('.')[0])

missings = 0
problems = 0
count = 0
root = 'metasploit-framework'

if args.output:
  o = open(args.output, 'w')

def print_or_write(line):
  if args.output:
    o.write("%s\n" %(line))
    return
  print(line)

print_or_write('# Documentation Issue Finder\n')
print_or_write('Generated: %s\n' %(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

if not (show_all):
    if not (show_issues):
        print_or_write('## Modules Without Documentation\n')
        for i in sorted(modules):
            if i not in docs:
                missings += 1
                print_or_write('+ [ ] %s%s' %(root, i.split('metasploit-framework')[1]))
        print_or_write('\n%s modules have no documentation.' %(missings))
    else:
        print_or_write('## Docs Without Modules\n')
        for i in sorted(docs):
            if i not in modules:
                problems += 1
                print_or_write('+ [ ] %s%s' %(root, i.split('metasploit-framework')[1]))
        print_or_write('\n%s doc files do not correspond to any module.' %(problems))
else:
    count = 0
    if not (show_issues):
        print_or_write('## Modules Without Documentation\n')
        for i in sorted(modules):
            if i in docs:
                print_or_write('+ [x] %s%s' %(root, i.split('metasploit-framework')[1]))
            else:
                print_or_write('+ [ ] %s%s' %(root, i.split('metasploit-framework')[1]))
                count += 1
        print_or_write('\n%s modules out of %s (%d%%) have no documentation.' %(count, len(modules), float(count)/len(modules) * 100.0))
    else:
        print_or_write('## Docs Without Modules\n')
        for i in sorted(docs):
            if i in modules:
                print_or_write('+ [x] %s%s' %(root, i.split('metasploit-framework')[1]))
            else:
                print_or_write('+ [ ] %s%s' %(root, i.split('metasploit-framework')[1]))
                count += 1
        print_or_write('\n%s doc files out of %s do not correspond to any module.' %(count, len(docs)))

if args.output:
  o.close()
