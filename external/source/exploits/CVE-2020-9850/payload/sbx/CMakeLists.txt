set(HOME $ENV{HOME})
set(WEBKIT_DIR ${HOME}/WebKit)

add_executable(sbx safari.mm cvm.cc safari.mm)
add_executable(cvm_side cvm_side.cc)

add_custom_target(
	threadexec
	COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/threadexec
)

add_dependencies(cvm_side loader bundle.hh)
add_dependencies(sbx cvm_side threadexec)

target_include_directories(cvm_side
	PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../root
)

target_include_directories(sbx
PUBLIC
threadexec/include
${WEBKIT_DIR}/Source/WebCore/platform/network/cf 
${WEBKIT_DIR}/Source/WebCore/platform/network 
${WEBKIT_DIR}/Source/WebKit/Shared/API 
${WEBKIT_DIR}/WebKitBuild/Release/include 
${WEBKIT_DIR}/WebKitBuild/Release/usr/local/include 
${WEBKIT_DIR}/WebKitBuild/WTF.build/Release/WTF.build/DerivedSources 
)

target_compile_options(sbx PUBLIC -DBINARY_DIR="${CMAKE_BINARY_DIR}" -fmessage-length=0 -fdiagnostics-show-note-include-stack -fmacro-backtrace-limit=0 -std=gnu++1z -stdlib=libc++ -Wno-trigraphs -fno-exceptions -fno-rtti -fno-sanitize=vptr -fpascal-strings -O3 -fno-common -Wno-missing-field-initializers -Wunreachable-code -Wnon-virtual-dtor -Wno-overloaded-virtual -Wno-exit-time-destructors -Wno-missing-braces -Wparentheses -Wswitch -Wunused-function -Wno-unused-label -Wno-unused-parameter -Wunused-value -Wempty-body -Wuninitialized -Wno-unknown-pragmas -Wno-shadow -Wno-four-char-constants -Wno-conversion -Wconstant-conversion -Wint-conversion -Wbool-conversion -Wenum-conversion -Wno-float-conversion -Wnon-literal-null-conversion -Wobjc-literal-conversion -Wsign-compare -Wno-shorten-64-to-32 -Wnewline-eof -Wno-c++11-extensions -DNDEBUG -DU_DISABLE_RENAMING=1 -DU_SHOW_CPLUSPLUS_API=0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.15.sdk -fasm-blocks -fstrict-aliasing -Wdeprecated-declarations -Winvalid-offsetof -g -fvisibility=hidden -fvisibility-inlines-hidden -fno-threadsafe-statics -Wno-sign-conversion -Winfinite-recursion -Wmove -Wcomma -Wblock-capture-autoreleasing -Wstrict-prototypes -Wrange-loop-analysis -Wno-semicolon-before-method-body -isystem /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.15.sdk/usr/local/include
-Wall -Wextra -Wcast-qual -Wchar-subscripts -Wconditional-uninitialized -Wextra-tokens -Wformat=2 -Winit-self -Wmissing-format-attribute -Wmissing-noreturn -Wpacked -Wpointer-arith -Wredundant-decls -Wundef -Wwrite-strings -Wexit-time-destructors -Wglobal-constructors -Wtautological-compare -Wimplicit-fallthrough -F${WEBKIT_DIR}/WebKitBuild/Release -iframework /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks
-Wno-unused-private-field)

target_link_libraries(sbx "-framework JavaScriptCore" "-framework CoreFoundation" "-framework Foundation" "-lthreadexec")

target_link_options(sbx PUBLIC -F${WEBKIT_DIR}/WebKitBuild/Release
-target x86_64-apple-macos10.15
-L${CMAKE_CURRENT_SOURCE_DIR}/threadexec/lib
)
