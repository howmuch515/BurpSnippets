from burp import IBurpExtender, IRequestInfo, IContextMenuFactory
from java.io import PrintWriter
from javax.swing import JMenu, JMenuItem, JFileChooser

# File I/O
from java.io import File, FileOutputStream

# Path
from java.net import URI


class BurpExtender(IBurpExtender, IRequestInfo, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "Paste a snippet"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Paste a snippet")
        callbacks.registerContextMenuFactory(self)

        # obtain our output and error streams
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Installed BurpSnippets.")

    def createMenuItems(self, invocation):
        menu = JMenu(self._actionName)
        self._menu_item = JMenuItem("snippets",
                                    None,
                                    actionPerformed=lambda x,
                                    inv=invocation: self.Action(inv),)
        menu.add(self._menu_item)
        return [menu]

    def Action(self, invocation):
        try:
            http_traffic = invocation.getSelectedMessages()
            traffic_length = len(http_traffic)
            counter = 0
            self._output_dir = u"/tmp"

            # choose output directory
            filechooser = JFileChooser()
            filechooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

            selected = filechooser.showSaveDialog(self._menu_item)
            if selected == JFileChooser.APPROVE_OPTION:
                f = filechooser.getSelectedFile()
                self._output_dir = f.getAbsolutePath()

            self._stdout.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

            while len(http_traffic) > 0:
                counter += 1
                target_traffic = http_traffic.pop()
                analyzedRequest = self._helpers.analyzeRequest(
                    target_traffic
                )
                analyzedResponse = self._helpers.analyzeResponse(
                    target_traffic.getResponse()
                )

                status_code = analyzedResponse.getStatusCode()
                mime_type = analyzedResponse.getStatedMimeType()
                url = analyzedRequest.getUrl()
                body_offset = analyzedResponse.getBodyOffset()

                # Skip empty response.
                if len(target_traffic.getResponse()[body_offset:]) <= 0:
                    self._stdout.printf("[%d/%d]\n", counter, traffic_length)
                    self._stdout.println("[-] %s's response is empty.", url)
                    continue

                # resolve filename from url.
                file_name = self.extract_filename(url)

                # check extention.
                if not self.has_extention(file_name):
                    ex = self.guess_extention(mime_type,
                                              target_traffic.getResponse())
                    file_name = file_name + "." + ex

                file_path = self._output_dir + u"/" + file_name.encode('utf-8')
                self._stdout.printf("[%d/%d]\n", counter, traffic_length)
                self._stdout.printf("url: %s\n", url)
                self._stdout.printf("status_code: %d\n", status_code)
                self._stdout.printf("mime_type: %s\n", mime_type)
                self._stdout.printf("body_offset: %d\n", body_offset)

                # extract object
                self.extract_obj(file_path,
                                 target_traffic.getResponse(),
                                 body_offset)

            self._stdout.printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")

        except Exception as e:
            self._stderr.println("[!] In Action.")
            self._stderr.println(e)

    def extract_filename(self, url):
        uri = url.toURI()
        path = uri.getPath().encode('utf-8')
        file_name = path.split(u"/")[-1]
        return file_name

    def has_extention(self, file_name):
        return len(file_name.split(".")) > 1

    def guess_extention(self, mime, res):
        if mime == u"JPEG":
            return u"jpg"
        elif mime == u"GIF":
            return u"gif"
        elif mime == u"PNG":
            return u"png"
        elif mime == u"HTML":
            return u"html"
        elif mime == u"JSON":
            return u"json"
        elif mime == u"XML":
            return u"xml"
        elif mime == u"scrip":
            # Only javascript is supported.
            return u"js"
        elif mime == u"text":
            return u"txt"
        elif mime == u"image":
            return u"ico"
        else:
            return u""

    def extract_obj(self, file_path, res, offset):
        try:
            f = File(file_path)

            # check same name file.
            counter = 0
            while True:

                # The same file name is not exists.
                if not f.exists():
                    break

                # Count up the file name.
                counter += 1
                stem = u"".join(file_path.split(u".")[:-1])
                ex = file_path.split(u".")[-1]

                _file_path = u"{}({}).{}".format(stem, counter, ex)
                f = File(_file_path)

            fos = FileOutputStream(f)

            fos.write(res[offset:])
            self._stdout.printf("save as \"%s\".\n\n", f.getPath())

            fos.close()

        except Exception as e:
            self._stderr.println("[!] In extract_obj.")
            self._stderr.println(e)
