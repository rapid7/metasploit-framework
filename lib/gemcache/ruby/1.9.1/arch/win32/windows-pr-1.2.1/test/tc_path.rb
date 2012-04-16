#####################################################################
# tc_path.rb
#
# Test case for the Windows::Path module.
#####################################################################
require "windows/path"
require "test/unit"

class PathFoo
   include Windows::Path
end

class TC_Windows_Path < Test::Unit::TestCase
   def setup
      @foo  = PathFoo.new
      @path = "C:\\"
   end

   def test_numeric_constants
      assert_equal(0x0000, PathFoo::GCT_INVALID)
      assert_equal(0x0001, PathFoo::GCT_LFNCHAR)
      assert_equal(0x0002, PathFoo::GCT_SHORTCHAR)
      assert_equal(0x0004, PathFoo::GCT_WILD)
      assert_equal(0x0008, PathFoo::GCT_SEPARATOR)
   end

   def test_method_constants
      assert_not_nil(PathFoo::PathAddBackslash)
      assert_not_nil(PathFoo::PathAddExtension)
      assert_not_nil(PathFoo::PathAppend)
      assert_not_nil(PathFoo::PathBuildRoot)
      assert_not_nil(PathFoo::PathCanonicalize)
      assert_not_nil(PathFoo::PathCombine)
      assert_not_nil(PathFoo::PathCommonPrefix)
      assert_not_nil(PathFoo::PathCompactPath)
      assert_not_nil(PathFoo::PathCompactPathEx)
      assert_not_nil(PathFoo::PathCreateFromUrl)
      assert_not_nil(PathFoo::PathFileExists)
      assert_not_nil(PathFoo::PathFindExtension)
      assert_not_nil(PathFoo::PathFindFileName)
      assert_not_nil(PathFoo::PathFindNextComponent)
      assert_not_nil(PathFoo::PathFindOnPath)
      assert_not_nil(PathFoo::PathFindSuffixArray)
      assert_not_nil(PathFoo::PathGetArgs)
      assert_not_nil(PathFoo::PathGetCharType)
      assert_not_nil(PathFoo::PathGetDriveNumber)
      assert_not_nil(PathFoo::PathIsContentType)
      assert_not_nil(PathFoo::PathIsDirectory)
      assert_not_nil(PathFoo::PathIsDirectoryEmpty)
      assert_not_nil(PathFoo::PathIsFileSpec)
      #assert_not_nil(PathFoo::PathIsHTMLFile)
      assert_not_nil(PathFoo::PathIsLFNFileSpec)
      assert_not_nil(PathFoo::PathIsNetworkPath)
      assert_not_nil(PathFoo::PathIsPrefix)
      assert_not_nil(PathFoo::PathIsRelative)
      assert_not_nil(PathFoo::PathIsRoot)
      assert_not_nil(PathFoo::PathIsSameRoot)
      assert_not_nil(PathFoo::PathIsSystemFolder)
      assert_not_nil(PathFoo::PathIsUNC)
      assert_not_nil(PathFoo::PathIsUNCServer)
      assert_not_nil(PathFoo::PathIsUNCServerShare)
      assert_not_nil(PathFoo::PathIsURL)
      assert_not_nil(PathFoo::PathMakePretty)
      assert_not_nil(PathFoo::PathMakeSystemFolder)
      assert_not_nil(PathFoo::PathMatchSpec)
      assert_not_nil(PathFoo::PathParseIconLocation)
      assert_not_nil(PathFoo::PathQuoteSpaces)
      assert_not_nil(PathFoo::PathRelativePathTo)
      assert_not_nil(PathFoo::PathRemoveArgs)
      assert_not_nil(PathFoo::PathRemoveBackslash)
      assert_not_nil(PathFoo::PathRemoveBlanks)
      assert_not_nil(PathFoo::PathRemoveExtension)
      assert_not_nil(PathFoo::PathRemoveFileSpec)
      assert_not_nil(PathFoo::PathRenameExtension)
      assert_not_nil(PathFoo::PathSearchAndQualify)
      assert_not_nil(PathFoo::PathSetDlgItemPath)
      assert_not_nil(PathFoo::PathSkipRoot)
      assert_not_nil(PathFoo::PathStripPath)
      assert_not_nil(PathFoo::PathStripToRoot)
      assert_not_nil(PathFoo::PathUndecorate)
      assert_not_nil(PathFoo::PathUnExpandEnvStrings)
      assert_not_nil(PathFoo::PathUnmakeSystemFolder)
      assert_not_nil(PathFoo::PathUnquoteSpaces)
   end

   def teardown
      @foo  = nil
      @path = nil
   end
end
