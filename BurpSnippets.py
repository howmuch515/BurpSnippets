from burp import IBurpExtender, IRequestInfo, IContextMenuFactory
from java.io import File
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import JMenu, JMenuItem, JFileChooser

import json, jarray

from java.awt import Toolkit
from java.awt.datatransfer import Clipboard
from java.awt.datatransfer import StringSelection

# snippets file path.
SNIPPETS_FILE_PATH = "SNIPPETS.json"


class BurpExtender(IBurpExtender, IRequestInfo, IContextMenuFactory):
    def __init__(self):
        self.snippets_file_path = SNIPPETS_FILE_PATH

    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "Paste a snippet"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpSnippets")
        callbacks.registerContextMenuFactory(self)

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Installed BurpSnippets.")

    def createMenuItems(self, invocation):
        menu = JMenu(self._actionName)

        # create import file menu.
        import_menu = JMenu("import file")

        # JSON dictionary file import
        as_json_menu_item = JMenuItem("as JSON or TOML")
        as_json_menu_item.actionPerformed = self.generateSelectFileAction(
            invocation, as_json_menu_item)
        import_menu.add(as_json_menu_item)
        menu.add(import_menu)
        menu.addSeparator()

        # load snippets json file.
        snippets_data = None
        try:
            with open(self.snippets_file_path, "r") as f:
                snippets_data = json.load(f)
        except Exception as e:
            print("Load JSON Error!")
            print(e)

        # create payload menu.

        # # if snippets_data is not set.
        if snippets_data is None:
            return [menu]

        try:
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

        except Exception as e:
            print("Convert snippets Error!")
            print(e)

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

    def generateSelectFileAction(self, invocation, parent_component):
        burp_extender_obj = self

        def selectSnippetsFile(self):
            fc = JFileChooser()
            filter = FileNameExtensionFilter("JSON or TOML", ["json", "toml"])
            fc.setFileFilter(filter)
            result = fc.showOpenDialog(parent_component)
            if result == JFileChooser.APPROVE_OPTION:
                f = fc.getSelectedFile()
                burp_extender_obj.snippets_file_path = fc.getName(f)

        return selectSnippetsFile
