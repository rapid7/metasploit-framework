import os
import sys
import psutil
import time
import multiprocessing
import unittest
import xmlrunner

Artifacts = ""

def Worker():

    while True:
        time.sleep(64)

    return

class TestMetasploit(unittest.TestCase):

    def setUp(self):

        self.worker = multiprocessing.Process(name="Worker",  target=Worker)
        self.worker.start()

        return

    def tearDown(self):

        self.worker.terminate()

        return

    def testMetasploit(self):

        process = psutil.Process(self.worker.pid)
        process.username()

        print("{0}\\inject.exe {1} {0}\\Metasploit.dll".format(Artifacts, self.worker.pid))
        os.system("{0}\\inject.exe {1} {0}\\Metasploit.dll".format(Artifacts, self.worker.pid))

        self.assertRaises(psutil.AccessDenied, process.username)

        return

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("{} {Absolute Path To Artifacts Directory}")
        sys.exit(-1)

    print("{} {}".format(sys.argv[0], sys.argv[1]))

    Artifacts = sys.argv[1]

    with open("{}\\Results.xml".format(Artifacts), "wb") as file:
        unittest.main(argv=[sys.argv[0]], testRunner=xmlrunner.XMLTestRunner(output=file),
                      failfast=False, buffer=False, catchbreak=False)

    sys.exit(0)