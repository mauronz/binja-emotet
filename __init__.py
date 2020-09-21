import sys
import os
import json
import struct
import string
import traceback
import time

from binaryninjaui import (UIAction, UIActionHandler, Menu)
from binaryninja import user_plugin_path, LowLevelILOperation
from binaryninja.highlevelil import HighLevelILInstruction
from binaryninja.function import Variable
from binaryninja.types import Symbol, SymbolType


#plugin_path = os.path.realpath(os.path.join(user_plugin_path(), "emotet_deobf"))
plugin_path = os.path.dirname(__file__)
func_dict = dict()
var_name_counts = dict()


def setup_hashdict(xor_key):
    with open(os.path.join(plugin_path, "exports.json"), "r") as f:
        apis = json.loads(f.read())
    all_names = list()
    for l in apis.values():
        for sym in l:
            if len(sym["name"]) > 0:
                all_names.append(sym["name"])
            hsh = 0
            for c in sym["name"]:
                hsh = ((hsh << 6) + ord(c) + (hsh << 0x10) - hsh) & 0xffffffff
            hsh ^= xor_key
            func_dict[hsh] = sym["name"]


def find_xor_key(function):
    for bb in function.llil:
        for instr in bb:
            if len(instr.operands) == 2 and instr.operands[1].operation == LowLevelILOperation.LLIL_XOR:
                for operand in instr.operands[1].operands:
                    if operand.operation == LowLevelILOperation.LLIL_CONST:
                        return operand.operands[0]
    return 0


def update_get_api_call(bv, xref):
    print("[*] Doing 0x{:x}".format(xref.address))
    hash_value = None
    cur_addr = xref.address - 1
    while hash_value is None:
        prev = None
        while not prev:
            cur_addr -= 1
            prev = xref.function.get_low_level_il_at(cur_addr)
        if prev.operation == LowLevelILOperation.LLIL_SET_REG and prev.operands[0].name == "edx":
            v = prev.operands[1].operands[0]
            if isinstance(v, int):
                hash_value = v
            else:
                break
        if prev.address == xref.function.start:
            break

    if hash_value is None:
        print("[-] Error: hash not found")
        return 1
    if hash_value not in func_dict:
        print("[-] Error: unknown hash")
        return 2

    api_name = func_dict[hash_value]
    var_key = (xref.function, api_name)
    if var_key not in var_name_counts:
        var_name_counts[var_key] = 1
        final_name = api_name
    else:
        final_name = "{:s}_{:d}".format(api_name, var_name_counts[var_key])
        var_name_counts[var_key] += 1
    bv.set_comment_at(xref.address, api_name)
    xref.function.create_user_address_tag(xref.address, bv.tag_types["Library"], api_name)
    for hl_bb in xref.function.hlil:
        for instr in hl_bb:
            if xref.address == instr.address:
                var = instr.operands[0]
                while isinstance(var, HighLevelILInstruction):
                    var = var.operands[0]
                if not isinstance(var, Variable):
                    continue
                xref.function.create_user_var(var, var.type, final_name)
                next_instr = xref.function.get_low_level_il_at(xref.address + 5)
                if next_instr.operation == LowLevelILOperation.LLIL_STORE and next_instr.operands[1].operands[0].name == "eax":
                    mem_addr = next_instr.operands[0].operands[0]
                    symbol = Symbol(SymbolType.DataSymbol, mem_addr, "_" + api_name)
                    bv.define_user_symbol(symbol)
                return 0
    return -1


def find_dynamic_apis(bv):
    get_api_func = None
    for func in bv.functions:
        first_bb = func.basic_blocks[0]
        for instr in first_bb:
            for token in instr[0]:
                if token.text == "0x78":
                    get_api_func = func
                    break
            if get_api_func:
                break
        if get_api_func:
            break
    print("[*] get_api: 0x{:x}".format(get_api_func.start))

    xor_key = find_xor_key(get_api_func)
    if xor_key == 0:
        print("[-] Error: couldn't find the XOR key in the get_api function")

    print("[*] XOR key: 0x{:x}".format(xor_key))
    setup_hashdict(xor_key)

    get_api_func.name = "get_api"
    visited_funcs = list()
    xrefs = bv.get_code_refs(get_api_func.start)
    for xref in xrefs:
        res = update_get_api_call(bv, xref)
        if res == 1 and xref.function not in visited_funcs:
            visited_funcs.append(xref.function)
            xrefs2 = bv.get_code_refs(xref.function.start)
            for xref2 in xrefs2:
                update_get_api_call(bv, xref2)


def decrypt_strings(bv):
    data_section = bv.get_section_by_name(".data")
    data = bv.read(data_section.start, data_section.end - data_section.start)

    printables = [ord(c) for c in string.printable]

    for i in range(0, len(data) - 4, 4):
        key, size = struct.unpack("<2I", data[i:i+8])
        size ^= key
        if size > 0 and size < 400 and i + size < len(data):
            byte_key = data[i:i+4]
            decrypted = bytearray()
            valid = True
            for j in range(size):
                char = data[i+8+j] ^ byte_key[j % 4]
                if char not in printables:
                    valid = False
                    break
                decrypted.append(char)
            if valid:
                sym_addr = data_section.start + i
                s = bytes(decrypted).decode()
                sym_name = s[:20].strip()
                for c in " \t\r\n":
                    sym_name = sym_name.replace(c, "_")
                sym_name = "str_" + sym_name
                symbol = Symbol(SymbolType.DataSymbol, sym_addr, sym_name)
                bv.define_user_symbol(symbol)
                bv.write(sym_addr, s + "\x00")


def launch_plugin(context):
    bv = context.binaryView
    decrypt_strings(bv)
    find_dynamic_apis(bv)


UIAction.registerAction("Emotet Deobufscator")
UIActionHandler.globalActions().bindAction("Emotet Deobufscator", UIAction(launch_plugin))
Menu.mainMenu("Tools").addAction("Emotet Deobufscator", "Emotet Deobufscator")