// Based on the example from http://www.java2s.com/Code/Java/JDK-6/CompilingfromMemory.htm

package javaCompile;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.lang.String;

import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import javax.tools.JavaFileObject.Kind;

public class CompileSourceInMemory {

	public static boolean CompileFromMemory(String strClass, String strCodeContent) {
		String[] classNames	= { strClass };
		String[] codeContent 	= { strCodeContent };
		return CompileFromMemory(classNames, codeContent, null);
	}

	public static boolean CompileFromMemory(String[] classNames, String[] codeContent) {
		return CompileFromMemory(classNames, codeContent, null);
	}

	public static boolean CompileFromMemory(String[] classNames, String[] codeContent, String[] compOptions) {
		
		List<String> compOptList = null;
		if (compOptions != null) { compOptList = Arrays.asList(compOptions); }
		
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

		// Need to add a check that classNames.length == codeContent.length, else we're fubared.
		List<JavaFileObject> files = new ArrayList<JavaFileObject> () ;
		int i = 0;
		for (String codePage : codeContent) {
			files.add(new JavaSourceFromString(classNames[i], codePage));
			i++;
		}

		Iterable<? extends JavaFileObject> compilationUnits = files;
		
		JavaCompiler.CompilationTask task = compiler.getTask(null, null, null, compOptList, null, compilationUnits);
		
		boolean success = task.call();

		return success;

	}
}

class JavaSourceFromString extends SimpleJavaFileObject {
	final String code;

	JavaSourceFromString(String name, String code) {
		super(URI.create("string:///" + name.replace('.','/') + Kind.SOURCE.extension),Kind.SOURCE);
		this.code = code;
	}

	@Override
	public CharSequence getCharContent(boolean ignoreEncodingErrors) {
		return code;
	}
}

