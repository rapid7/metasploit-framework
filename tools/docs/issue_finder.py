import os
import sys
import argparse


try:
    import glob
except ImportError:
    print("Please install glob package")
    sys.exit()
    
parser = argparse.ArgumentParser(epilog='Choose options in order to print the wanted information about modules and their documentations.', prefix_chars='--', )
parser.add_argument('-m', '--modules', type=str, default='auxiliary/scanner', help='Choose the modules category to work with. Respect the module category names as in metasploit-framework. Only one category should be passed, e.g. "auxiliary/admin", "exploits/android/browser" or "encoders" are valid entries.')
parser.add_argument('--show_all', action="store_true", default=False, help='Show the complete list of items. In default mode, modules with documentation are marked "[x]" and modules without are marked "[ ]". In issues mode, documentation files without module are marked "[ ]" and documentation files with module are marked "[x]".')
parser.add_argument('--show_issues', action="store_true", default=False, help='Show the list of documentation files without modules instead of modules withouth documentation file.')
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

missings = []
problems = []
count = 0
	
if not (show_all):
	if not (show_issues):
		for i in modules:
			if i not in docs:
				missings.append(i)
		for i in sorted(missings):
			print('+ [ ] ' + '/metasploit-framework' + i.split('metasploit-framework')[1])
		print(str(len(missings)) + ' modules have no documentation.')
	else:
		for i in docs:
			if i not in modules:
				problems.append(i)
		for i in sorted(problems):
			print('+ [ ] ' + '/metasploit-framework' + i.split('metasploit-framework')[1])
		print(str(len(problems)) + ' doc files do not correspond to any module.')
		

else:
	count = 0
	if not (show_issues):
		for i in sorted(modules):		
			if i in docs:
				print('+ [x] ' + '/metasploit-framework' + i.split('metasploit-framework')[1])
			else:
				print('+ [ ] ' + '/metasploit-framework' + i.split('metasploit-framework')[1])
				count += 1
		print(str(count) + ' modules out of ' + str(len(modules)) + ' have no documentation.')
	else:
		for i in sorted(docs):
			if i in modules:
				print('+ [x] ' + '/metasploit-framework' + i.split('metasploit-framework')[1])
			else:
				print('+ [ ] ' + '/metasploit-framework' + i.split('metasploit-framework')[1])
				count += 1
		print(str(count) + ' doc files out of ' + str(len(docs)) + ' do not correspond to any module.')			
	

