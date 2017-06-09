import idaapi
import idautils

f_imports = []
M_NAME = "MSVBVM60"
f_defs = {
    "__vbaR8Str" : {
        "type" : "long double __usercall __vbaR8Str@<st0>(char *pstr);",
        "comment" : "converts a string into a double"
    },
    "__vbaR8Var" : {
        "type" : "long double __usercall __vbaR8Var@<st0>(__int64 *pintStruct);",
        "comment" : "converts a long int(?) into a double. Addr is *pintStruct+8"
    }
}

def imports_cb(ea, name, ord):
    f_imports.append(name)
    if name in f_defs.keys():
        idc.SetType(ea, f_defs[name]["type"])
        MakeComm(ea, f_defs[name]["comment"])
    return True

nimps = idaapi.get_import_module_qty()
for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if name == M_NAME:
        print "Found module => %s" % M_NAME
        idaapi.enum_import_names(i, imports_cb)
        print "%d named functions were discovered" % len(f_imports)
