import logging
import ntpath
import time

import metasploit.module as module

OUTPUT_FILENAME = '__' + str(time.time())


def pre_run_hook(args):
    if 'rhost' in args:
        module.LogHandler.setup(msg_prefix="{0} - ".format(args['rhost']))
    else:
        module.LogHandler.setup()

class RemoteShell(object):
    def __init__(self, share, transferClient):
        self._share = share
        self._output = '\\' + OUTPUT_FILENAME
        self._outputBuffer = ''

        self.__transferClient = transferClient
        self._noOutput = False

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self._noOutput = True

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self._outputBuffer.strip('\r\n')) > 0:
            self._outputBuffer = ''
        else:
            self._pwd = ntpath.normpath(ntpath.join(self._pwd, s))
            self.execute_remote('cd ')
            self._pwd = self._outputBuffer.strip('\r\n')
            self._outputBuffer = ''

    def do_get(self, src_path):
        try:
            newPath = ntpath.normpath(ntpath.join(self._pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)
            filename = ntpath.basename(tail)
            fh = open(filename, 'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            if os.path.exists(filename):
                os.remove(filename)

    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = string.replace(dst_path, '/', '\\')

            pathname = ntpath.join(ntpath.join(self._pwd, dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1]+'$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))

    def do_exit(self, _):
        return True

    def onecmd(self, line):
        self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self._outputBuffer += data

        if self._noOutput is True:
            self._outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self._share, self._output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self._share, self._output)

    def send_data(self, data):
        self.execute_remote(data)
        if self._noOutput is False:
            module.log(self._outputBuffer)
        self._outputBuffer = ''
