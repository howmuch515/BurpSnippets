from burp import IBurpExtender, IRequestInfo, IContextMenuFactory
from java.io import PrintWriter
from javax.swing import JMenu, JMenuItem, JFileChooser
from java.lang import String

# File I/O
from java.io import File, FileOutputStream
import json, jarray
from java.lang import Object as javaObject
from java.awt import Toolkit
from java.awt.datatransfer import Clipboard
from java.awt.datatransfer import StringSelection

# snippets file path.
SNIPPETS_FILE_PATH = "snippets.json"


class BurpExtender(IBurpExtender, IRequestInfo, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "Paste a snippet"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpSnippets")
        callbacks.registerContextMenuFactory(self)

        # obtain our output and error streams
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Installed BurpSnippets.")

    def createMenuItems(self, invocation):
        menu = JMenu(self._actionName)

        # load snippets json file.
        snippets_data = ""
        with open(SNIPPETS_FILE_PATH, "r") as f:
            snippets_data = json.load(f)

        # create payload menu.
        for i in snippets_data:
            type_menu = JMenu(i["type"])
            for j in i["items"]:
                key = j["key"]
                payload = j["value"]

                a = JMenuItem(
                    key, None,
                    actionPerformed=self.generateClickAction(
                        invocation, payload),)
                type_menu.add(a)
            menu.add(type_menu)
        return [menu]

    def generateClickAction(self, invocation, payload):

        def click_action(self):
            # Copy payload to clipboard
            kit = Toolkit.getDefaultToolkit()
            clip = kit.getSystemClipboard()

            ss = StringSelection(payload)
            clip.setContents(ss, None)

            # Paste payload to text area
            selectedIndex = invocation.getSelectionBounds()
            req = invocation.getSelectedMessages()[0]
            request = req.getRequest()

            # convert data into bytes list.
            request_list = list(request)
            payload_list = map(ord, bytes(payload))

            # insert payload.
            del request_list[selectedIndex[0]: selectedIndex[1]]
            request_list[selectedIndex[0]: selectedIndex[0]] = payload_list

            # override request.
            request = jarray.array(request_list, "b")
            req.setRequest(request)

        return click_action
