import idaapi
import Gopclntab
import Utils
import Firstmoduledata
import Types
import idc
import idautils
import pygore
import codecs

class GoSettings(object):


    def __init__(self):
        self.storage = {}
        self.bt_obj = Utils.get_bitness(idc.BeginEA())
        self.structCreator = Utils.StructCreator(self.bt_obj)
        self.processor = None
        self.typer = None
        self.binaryPath = idc.GetInputFilePath()
        self.structsDef = {}

    def getVal(self, key):
        if key in self.storage:
            return self.storage[key]
        return None

    def setVal(self, key, val):
        self.storage[key] = val

    def getGopcln(self):
        gopcln_addr = self.getVal("gopcln")
        if gopcln_addr is None:
            gopcln_addr = Gopclntab.findGoPcLn()
            self.setVal("gopcln", gopcln_addr)
            print "gopcln_addr is " + str(gopcln_addr)
        return gopcln_addr

    def findModuleData(self):
        gopcln_addr = self.getGopcln()
        fmd = Firstmoduledata.findFirstModuleData(gopcln_addr, self.bt_obj)
        self.setVal("firstModData", fmd)
        return

    def tryFindGoVersion(self):
        f = pygore.GoFile(self.binaryPath)
        v = f.get_compiler_version()
        f.close()
        return "Go Compiler Version should be %s" % (v.name)
    
    def outputBinaryPackageList(self):
    	f = pygore.GoFile(self.binaryPath)
        gopkgs_1 = f.get_packages()
        gopkgs_2 = f.get_vendor_packages()
        gopkgs_3 = f.get_std_lib_packages()
        gopkgs_4 = f.get_unknown_packages()
        f.close()
        pkg_file = codecs.open(self.binaryPath + "_packages.txt", "w", encoding="utf-8")
        pkg_file.write("Current Package:\n")
        for i in gopkgs_1:
        	pkg_file.write(i.name + "\n")
        pkg_file.write("\n\nVendor Packages:\n")
        for i in gopkgs_2:
        	pkg_file.write(i.name + "\n")
        pkg_file.write("\n\nStandard Libraries:\n")
        for i in gopkgs_3:
        	pkg_file.write(i.name + "\n")
        pkg_file.write("\n\nUnclassified Packages:\n")
        for i in gopkgs_4:
        	pkg_file.write(i.name + "\n")
        pkg_file.close()
        print "Package info saved to " + self.binaryPath + "_packages.txt"
        return

    def renameFunctions(self):
        gopcln_tab = self.getGopcln()
        Gopclntab.rename(gopcln_tab, self.bt_obj)

    def _getStructDef(self,t):
        kinds = [ 
            "invalid",
            "bool",
	    "int",
	    "int8",
	    "int16",
	    "int32",
	    "int64",
	    "uint",
	    "uint8",
	    "uint16",
	    "uint32",
	    "uint64",
	    "uintptr",
	    "float32",
	    "float64",
	    "complex64",
	    "complex128",
	    "array",
	    "chan",
	    "func",
	    "interface",
	    "map",
	    "ptr",
	    "slice",
	    "string",
	    "struct",
	    "unsafe.Pointer"
        ]
        if kinds[t.kind] != "struct":
            return ""
        buf = "type %s struct{" % t.name
        for f in t.fields:
            if f.fieldAnon:
                buf += "\n\t%s" % f
            else:
                buf += "\n\t%s %s" % (f.fieldName, f.name)
        if len(t.fields) > 0:
            buf += "\n"
        return buf + "}"

    def renameStructs(self):
        f = pygore.GoFile(self.binaryPath)
        c = f.get_compiler_version()
        print('Compiler: {}\nTimestamp: {}\nSHA {}\n'.format(c.name, c.timestamp, c.sha))

        #pkgs = f.get_packages()
        types = f.get_types()
        f.close()
        struct_file = codecs.open(self.binaryPath + "_struct.txt", "w", encoding="utf-8")
        for t in types:
            Utils.rename(t.addr, t.name)
            self.structsDef[t.addr] = self._getStructDef(t)
            struct_file.write(str(t.addr) + " " + str(t.name) + "\n")
        print "Struct info saved to " + self.binaryPath + "_struct.txt"
        struct_file.close()
    
    def getStructDefByCursor(self):
        addr = idc.GetOperandValue(idc.here(),1)
        print self.structsDef[addr]

    def getVersionByString(self):
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 31 33", 16) != idc.BADADDR:
            return 'Go 1.13'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 31 32", 16) != idc.BADADDR:
            return 'Go 1.12'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 31 31", 16) != idc.BADADDR:
            return 'Go 1.11'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 31 30", 16) != idc.BADADDR:
            return 'Go 1.10'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 39", 16) != idc.BADADDR:
            return 'Go 1.9'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 38", 16) != idc.BADADDR:
            return 'Go 1.8'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 37", 16) != idc.BADADDR:
            return 'Go 1.7'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 36", 16) != idc.BADADDR:
            return 'Go 1.6'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 35", 16) != idc.BADADDR:
            return 'Go 1.5'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 34", 16) != idc.BADADDR:
            return 'Go 1.4'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 33", 16) != idc.BADADDR:
            return 'Go 1.3'
        if idc.FindBinary(0, idc.SEARCH_DOWN, "67 6f 31 2e 32", 16) != idc.BADADDR:
            return 'Go 1.2'

    def createTyper(self, typ):
        if typ == 0:
            self.typer = Types.Go12Types(self.structCreator)
        elif typ == 1:
            self.typer = Types.Go14Types(self.structCreator)
        elif typ == 2:
            self.typer = Types.Go15Types(self.structCreator)
        elif typ == 3:
            self.typer = Types.Go16Types(self.structCreator)
        elif typ == 4 or typ == 5:
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 6: #1.9
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 7: #1.10
            self.typer = Types.Go17Types(self.structCreator)

    def typesModuleData(self, typ):
        if typ < 2:
            return
        if self.getVal("firstModData") is None:
            self.findModuleData()
        fmd = self.getVal("firstModData")
        if fmd is None:
            return
        if self.typer is None:
            self.createTyper(typ)
        robase = None
        if typ == 4:
            beg, end, robase = Firstmoduledata.getTypeinfo17(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing17(beg, end, self.bt_obj, self, robase)
        elif typ == 5:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing17(beg, end, self.bt_obj, self, robase)
        elif typ == 6:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing19(beg, end, self.bt_obj, self, robase)
        elif typ == 7:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing19(beg, end, self.bt_obj, self, robase)
        else:
            beg, end = Firstmoduledata.getTypeinfo(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing(beg, end, self.bt_obj, self)
        print "%x %x %x" % (beg, end, robase)
        for i in self.processor:
            pass
        return