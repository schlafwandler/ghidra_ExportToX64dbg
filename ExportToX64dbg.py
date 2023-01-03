# Export function names to x64dbg
#@author schlafwandler
#@category Examples
#@keybinding 
#@menupath 
#@toolbar 

import json

def fixdata(obj_list):
    """
    transforms numbers to hexstring and module names to lowercase
    """
    for entry in obj_list:
        monitor.checkCanceled() # throws exception if canceled

        # fix addresses
        if "address" in entry:
            entry["address"] = hex(entry["address"])
        if "start" in entry:
            entry["start"] = hex(entry["start"])#[:-1] # strip trailing 'L'
        if "end" in entry:
            entry["end"] = hex(entry["end"])#[:-1] # strip trailing 'L'
        # fix module name
        if "module" in entry:
            entry["module"] = entry["module"].lower()


def export_json(filename, data, lowercase_modulename=True):
    monitor.setMessage("Exporting data")
    
    # data transformation
    for category in data.values():
        fixdata(category)

    with open(filename,"w") as f:
        json.dump(data,f,sort_keys=True,indent=4)


def main():
    output_filename = str(askFile("Select output file name","Save"))

    if "64" in str(currentProgram.getLanguage()):
        suffix = ".dd64"
    else:
        suffix = ".dd32"

    if not output_filename.endswith(suffix):
        output_filename = output_filename + suffix
    
    functions,function_labels,prototype_comments = get_functions_labels()
    data_labels = get_data_labels()
    bookmarks,bookmark_comments = get_bookmarks()
    statement_comments = get_clang_statements()
    comments = get_comments()

    data = dict()
    data["labels"] = function_labels + data_labels
    data["comments"] = prototype_comments + statement_comments + bookmark_comments + comments
    data["functions"] = functions
    data["bookmarks"] = bookmarks
    
    export_json(output_filename,data)

def get_functions_labels():
    monitor.setMessage("Collecting function labels and prototypes")

    functions           = list()
    labels              = list()
    prototype_comments  = list()
    module_name = currentProgram.getName()
    imagebase = currentProgram.getImageBase().getOffset()

    fm = currentProgram.getFunctionManager()
    for f in fm.getFunctionsNoStubs(1):
        monitor.checkCanceled() # throws exception if canceled

        if f.isExternal() or f.isThunk():
            next

        function_entry = dict()
        function_entry["module"]    = module_name
        function_entry["manual"]    = False
        function_entry["icount"]    = 0 # FIXME
        function_entry["start"]     = f.getBody().getMinAddress().getOffset() - imagebase
        function_entry["end"]       = f.getBody().getMaxAddress().getOffset() - imagebase
        functions.append(function_entry)

        # label
        label_entry = dict()
        label_entry["module"]   = module_name
        label_entry["manual"]   = False
        label_entry["address"]  = f.getEntryPoint().getOffset() - imagebase
        label_entry["text"]     = f.getName()
        labels.append(label_entry)

        # function prototype comment
        comment_entry = dict()
        comment_entry["module"]   = module_name
        comment_entry["manual"]   = False
        comment_entry["address"]  = f.getEntryPoint().getOffset() - imagebase
        comment_entry["text"]     = f.getPrototypeString(1,0)
        prototype_comments.append(comment_entry)

    return functions,labels,prototype_comments

def get_data_labels():
    monitor.setMessage("Collecting data labels")

    labels = list()
    module_name = currentProgram.getName()
    imagebase = currentProgram.getImageBase().getOffset()

    listing = currentProgram.getListing()
    for d in listing.getData(1):
        monitor.checkCanceled() # throws exception if canceled
        label = d.getLabel()
        path = d.getPathName()
        
        if label:
            text = label
        else:
            text = None

        if text:
            # function label
            label_entry = dict()
            label_entry["module"]   = module_name
            label_entry["manual"]   = False
            label_entry["address"]  = d.getAddress().getOffset() - imagebase
            label_entry["text"]     = text
            labels.append(label_entry)

    return labels

def get_bookmarks():
    monitor.setMessage("Collecting bookmarks")

    bookmarks = list()
    bookmark_comments = list()
    module_name = currentProgram.getName()
    imagebase = currentProgram.getImageBase().getOffset()

    bm = currentProgram.getBookmarkManager()
    for b in bm.getBookmarksIterator():
        monitor.checkCanceled() # throws exception if canceled
        
        if not b.getTypeString() == "Note":
            continue

        bookmark_entry = dict()
        bookmark_entry["module"]    = module_name
        bookmark_entry["address"]   = b.getAddress().getOffset() - imagebase
        bookmark_entry["manual"]    = False
        bookmarks.append(bookmark_entry)

        bookmark_comment_entry = dict()
        bookmark_comment_entry["module"]    = module_name
        bookmark_comment_entry["address"]   = b.getAddress().getOffset() - imagebase
        bookmark_comment_entry["manual"]    = False
        bookmark_comment_entry["text"]      = b.getCategory() + ": " + b.getComment()
        bookmark_comments.append(bookmark_comment_entry)

        comment_addr = (getInstructionAfter(getInstructionAfter(item.getFromAddress()))).getAddress()
        listing = currentProgram.getListing()
        codeUnit = listing.getCodeUnitAt(comment_addr)
        codeUnit.setComment(codeUnit.EOL_COMMENT, '[*] ' + decoded_str)

    return bookmarks, bookmark_comments
    
def get_clang_statements(): 
    monitor.setMessage("Collecting C statements")
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.decompiler import ClangStatement

    module_name = currentProgram.getName()
    imagebase = currentProgram.getImageBase().getOffset()

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    def token_walker(node,list):
        if type(node) == ClangStatement:
            list.append(node)
        else:
            for i in range(node.numChildren()):
                token_walker(node.Child(i),list)

    statement_nodes = list()
    function_manager = currentProgram.getFunctionManager()
    for f in function_manager.getFunctionsNoStubs(1):
        monitor.checkCanceled() # throws exception if canceled
        
        decres = decomp.decompileFunction(f,1000,monitor)
        token_walker(decres.getCCodeMarkup(),statement_nodes)

    statements = list()
    for node in statement_nodes:
        if node.getMinAddress() is not None:
            statement_entry = dict()
            statement_entry["module"]   = module_name
            statement_entry["address"]   = node.getMinAddress().getOffset() - imagebase
            statement_entry["manual"]    = False
            statement_entry["text"]    = node.toString()
            statements.append(statement_entry)

    return statements
        
def get_comments():
    monitor.setMessage("Collecting comments")

    from ghidra.app.util import DisplayableEol

    module_name = currentProgram.getName()
    imagebase = currentProgram.getImageBase().getOffset()

    comments = list()

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    funcs = fm.getFunctions(True) # True means iterate forward

    comment_types = { 
        0: 'EOL', 
        1: 'PRE', 
        2: 'POST',
        3: 'PLATE',
        4: 'REPEATABLE',
    }

    for func in funcs: 
        addrSet = func.getBody()
        codeUnits = listing.getCodeUnits(addrSet, True)
        for codeUnit in codeUnits:
            for i, comment_type in comment_types.items():
                comment = codeUnit.getComment(i)

                if comment is not None:
                    comment_entry = dict()
                    comment_entry["module"]    = module_name
                    comment_entry["address"]   = int(str(codeUnit.getAddress()), 16) - imagebase
                    comment_entry["manual"]    = False
                    comment_entry["text"]      = comment_type + ": " + comment
                    comments.append(comment_entry)

    return comments


main()