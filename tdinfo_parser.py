import binascii
import os
import sys
import ctypes

import idc
import ida_bytes
import ida_frame
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_netnode
import ida_segment
import ida_struct
import ida_segregs
import tdinfo_structs

ida_idaapi.require('tdinfo_structs')

TDINFO_MEMBER_INFO_END_MARKER = 0xC0
TDINFO_MEMBER_PADDING_MARKER = 0x40

class TdinfoParserException(Exception):
    pass

class TdinfoParserWrongInputFileCrcException(TdinfoParserException):
    pass

class TdinfoParserSymbolAlreadyAppliedException(TdinfoParserException):
    pass

class TdinfoParserIdaSetNameFailedException(TdinfoParserException):
    pass

class TdinfoParserIdaAddStrucFailedException(TdinfoParserException):
    pass

class TdinfoParserUnsupportedSymbolClassException(TdinfoParserException):
    pass

class TdinfoParserUnsupportedTypeException(TdinfoParserException):
    pass

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class TdinfoParser(object):
    def __init__(self):
        # A heuristic, since get_imagebase returns wrong result
        self._image_base = ida_segment.get_first_seg().start_ea
        self._parsed_exe = self._parse_exe_file()
        self._type_record_to_struct_tid = {}
        self._created_struct_union = set()

    @staticmethod
    def _find_exe_file():
        file_path = ida_nalt.get_input_file_path()

        if not os.path.isfile(file_path):
            file_path = ida_kernwin.ask_file(False, file_path, 'Input file')

        with open(file_path, 'rb') as file:
            file_crc32 = binascii.crc32(file.read()) & 0xFFFFFFFF

        original_crc32 = ida_nalt.retrieve_input_file_crc32() & 0xFFFFFFFF

        if original_crc32 != file_crc32:
            raise TdinfoParserWrongInputFileCrcException(
                'Expected 0x{:08X}, got 0x{:08X}'.format(original_crc32, file_crc32))

        return file_path

    @staticmethod
    def _parse_exe_file():
        input_file_path = TdinfoParser._find_exe_file()
        parsed_exe = tdinfo_structs.DOS_MZ_EXE_STRUCT.parse_file(input_file_path)

        print('Borland TLink symbolic information version: {}.{:02}'.format(
            parsed_exe.tdinfo_header.major_version,
            parsed_exe.tdinfo_header.minor_version))

        return parsed_exe
    
    def _name_type(self, symbol):
        if not symbol.type:
            return

        symbol_class = symbol.bitfield.symbol_class
        if symbol_class not in [tdinfo_structs.SymbolClass.STRUCT_UNION_OR_ENUM.name,
                                tdinfo_structs.SymbolClass.TYPEDEF.name]:
            return

        type_record = self._parsed_exe.type_records[symbol.type - 1]
        name = self._get_name_from_pool(symbol.index)
        assert(name is not None)

        if type_record.id == tdinfo_structs.TypeId.STRUCT.name or \
           type_record.id == tdinfo_structs.TypeId.UNION.name or \
           type_record.id == tdinfo_structs.TypeId.ENUM.name:
            if type_record.name != 0:
                assert(name == self._get_name_from_pool(type_record.name))
            else:
                type_record.name = symbol.index

    def _add_fake_name_to_pool(self, name):
        self._parsed_exe.name_pool.append(name)
        return len(self._parsed_exe.name_pool)

    def _get_name_from_pool(self, name_index):
        if name_index == 0:
            return None
        return str(self._parsed_exe.name_pool[name_index - 1])

    def _apply_global_symbol(self, symbol):
        symbol_ea = self._image_base + symbol.segment * 0x10 + symbol.offset
        symbol_name = self._get_name_from_pool(symbol.index)

        try:
            self._apply_type(symbol, symbol_ea)
        except TdinfoParserUnsupportedTypeException:
            pass

        if ida_name.get_name(symbol_ea) == symbol_name:
            raise TdinfoParserSymbolAlreadyAppliedException()

        if ida_name.set_name(symbol_ea, symbol_name):
            print('Applied name {} to address {:04X}:{:04X}'.format(
                symbol_name,
                self._image_base // 0x10 + symbol.segment,
                symbol.offset))
        else:
            raise TdinfoParserIdaSetNameFailedException()

    def _apply_type(self, symbol, symbol_ea):
        if not symbol.type:
            return

        type_record = self._parsed_exe.type_records[symbol.type - 1]
        type_flag, type_index = self._type_record_to_ida_type_flag(symbol.type)
            
        tid = None
        if type_flag == ida_bytes.stru_flag():
            tid = self._get_struct_tid(type_index)

        if tid == None:
            tid = ida_netnode.BADNODE

        if not ida_bytes.del_items(symbol_ea, ida_bytes.DELIT_SIMPLE, type_record.size):
            eprint('Failed to delete items at address {:04X}:{:04X}'.format(
                self._image_base // 0x10 + symbol.segment,
                symbol.offset))
            
        if not ida_bytes.create_data(symbol_ea, type_flag, type_record.size, tid):
            eprint('Failed to create data at address {:04X}:{:04X}'.format(
                self._image_base // 0x10 + symbol.segment,
                symbol.offset))

    def _type_record_to_ida_type_flag(self, index):
        type_record = self._parsed_exe.type_records[index - 1]
        type_id = type_record.id
        if type_id in [tdinfo_structs.TypeId.SCHAR.name,
                       tdinfo_structs.TypeId.UCHAR.name]:
            return ida_bytes.byte_flag(), index
        if type_id in [tdinfo_structs.TypeId.SINT.name,
                       tdinfo_structs.TypeId.UINT.name,
                       tdinfo_structs.TypeId.NEAR.name]:
            return ida_bytes.word_flag(), index
        if type_id in [tdinfo_structs.TypeId.SLONG.name,
                       tdinfo_structs.TypeId.ULONG.name,
                       tdinfo_structs.TypeId.FAR.name]:
            return ida_bytes.dword_flag(), index
        if type_id == tdinfo_structs.TypeId.ARRAY.name:
            return self._type_record_to_ida_type_flag(type_record.member_type)
        if type_id == tdinfo_structs.TypeId.STRUCT.name:
            return ida_bytes.stru_flag(), index
        if type_id == tdinfo_structs.TypeId.UNION.name:
            return ida_bytes.stru_flag(), index
        if type_id == tdinfo_structs.TypeId.FLOAT.name:
            return ida_bytes.float_flag(), index
        
        raise TdinfoParserUnsupportedTypeException()

    def _create_member_type(self, index):
        type_record = self._parsed_exe.type_records[index - 1]
        type_id = type_record.id
        if type_id == tdinfo_structs.TypeId.NEAR.name or \
            type_id == tdinfo_structs.TypeId.FAR.name or \
            type_id == tdinfo_structs.TypeId.ARRAY.name:
            self._create_member_type(type_record.member_type)
        elif type_id == tdinfo_structs.TypeId.STRUCT.name or \
            type_id == tdinfo_structs.TypeId.UNION.name or \
            type_id == tdinfo_structs.TypeId.ENUM.name:
            self._create_struct_union_enum(index - 1)

    def _create_struct_union_enum(self, i):
        type_record = self._parsed_exe.type_records[i]

        if type_record.id != tdinfo_structs.TypeId.STRUCT.name and \
           type_record.id != tdinfo_structs.TypeId.UNION.name and \
           type_record.id != tdinfo_structs.TypeId.ENUM.name:
            return

        if i in self._created_struct_union:
            return
        
        assert(type_record.class_type == 0)

        #TODO: Enums
        if type_record.id == tdinfo_structs.TypeId.ENUM.name:
            return
        
        is_union = type_record.id == tdinfo_structs.TypeId.UNION.name

        struct_name = self._get_name_from_pool(type_record.name)
        if struct_name is None:
            if type_record.id == tdinfo_structs.TypeId.STRUCT.name:
                struct_name = 'struct_' + str(i)
                type_record.name = self._add_fake_name_to_pool(struct_name)
            elif type_record.id == tdinfo_structs.TypeId.UNION.name:
                struct_name = 'union_' + str(i)
                type_record.name = self._add_fake_name_to_pool(struct_name)
            elif type_record.id == tdinfo_structs.TypeId.ENUM.name:
                struct_name = 'enum_' + str(i)
                type_record.name = self._add_fake_name_to_pool(struct_name)

        existing_struct_tid = ida_struct.get_struc_id(struct_name)
        if existing_struct_tid != ida_idaapi.BADADDR:
            assert(self._type_record_to_struct_tid.get(i) == None)
            self._created_struct_union.add(i)
            self._type_record_to_struct_tid[i] = existing_struct_tid
            return

        members = []
        offset = 0
        max_members_count = self._parsed_exe.tdinfo_header.members_count
        for member_index in range(type_record.member_type - 1, max_members_count + 1):
            member = self._parsed_exe.member_records[member_index]
            if member.info == TDINFO_MEMBER_INFO_END_MARKER:
                break

            if member.info == TDINFO_MEMBER_PADDING_MARKER:
                offset = (offset + 1) & ~1
                continue

            member_name = self._get_name_from_pool(member.name)
            member_type = self._parsed_exe.type_records[member.type - 1]
            self._create_member_type(member.type)

            type_flag, index = self._type_record_to_ida_type_flag(member.type)
            members.append((member_name, member_type.size, type_flag, offset))
            if not is_union:
                offset += member_type.size

        tid = ida_struct.add_struc(ida_idaapi.BADADDR, struct_name, is_union)
        if tid == ida_idaapi.BADADDR:
            raise TdinfoParserIdaAddStrucFailedException()

        struct_ptr = ida_struct.get_struc(tid)

        for name, size, flag, off in members:
            if not ida_struct.add_struc_member(struct_ptr,name,off,flag,ida_nalt.opinfo_t(),size):
                eprint('Failed to add member {} to struct {}.'.format(name, struct_name))

        self._created_struct_union.add(i)
        print('Created struct {}.'.format(struct_name))
        assert(self._type_record_to_struct_tid.get(i) == None)
        self._type_record_to_struct_tid[i] = tid

    def _get_struct_tid(self, type_index):
        return self._type_record_to_struct_tid[type_index-1]

    def _is_type_symbol(self, symbol):
        return symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.TYPEDEF.name

    def _is_global_symbol(self, symbol):
        return symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.STATIC.name
    
    def _create_segment(self, segment_record):
        seg_ea = self._image_base + segment_record.code_segment * 0x10 + segment_record.code_offset
        module = self._parsed_exe.module_records[segment_record.module - 1]
        module_name = self._get_name_from_pool(module.name)

        ida_segment.del_segm(seg_ea, 0)
        ida_segment.add_segm(segment_record.code_segment+(self._image_base // 0x10), \
                             seg_ea, seg_ea + segment_record.code_length, module_name, 'CODE')
        segment_ptr = ida_segment.getseg(seg_ea)
        ida_segment.set_segm_addressing(segment_ptr, 0)
        dseg  = ida_segment.get_segm_by_name('dseg')
        ida_segregs.set_default_sreg_value(segment_ptr, ida_segregs.R_ds, dseg.start_ea//0x10)
        print('Created segment {} at {:04X}:{:04X}'.format(
            module_name,
            self._image_base // 0x10 + segment_record.code_segment,
            segment_record.code_offset))
    
    def _rename_segment(self, segment_record):
        seg_ea = self._image_base + segment_record.code_segment * 0x10 + segment_record.code_offset
        module = self._parsed_exe.module_records[segment_record.module - 1]
        module_name = self._get_name_from_pool(module.name)
        segment_ptr = ida_segment.getseg(seg_ea)
        ida_segment.set_segm_name(segment_ptr, module_name)
        print('Renamed segment {} at {:04X}:{:04X}'.format(
            module_name,
            self._image_base // 0x10 + segment_record.code_segment,
            segment_record.code_offset))

    def _apply_segment(self, segment_record):
        seg_ea = self._image_base + segment_record.code_segment * 0x10 + segment_record.code_offset
        segment_ptr = ida_segment.getseg(seg_ea)

        if segment_ptr == None or segment_ptr.start_ea != seg_ea or segment_ptr.end_ea != seg_ea + segment_record.code_length:
            self._create_segment(segment_record)
        else:
            self._rename_segment(segment_record)

    def _apply_scopes(self, segment_record):
        first_scope_index = segment_record.scope_index - 1
        range_end = first_scope_index + segment_record.scope_count
        for scope_index in range(first_scope_index, range_end):
            scope_record = self._parsed_exe.scope_records[scope_index]
            self._apply_scope(segment_record, scope_record)

    def _apply_scope(self, segment_record, scope_record):
        if scope_record.parent == 0:
            scope_offset = scope_record.offset
        else:
            scope_offset = self._parsed_exe.scope_records[scope_record.parent - 1].offset
        scope_ea = self._image_base + segment_record.code_segment * 0x10 + scope_offset

        if scope_record.parent == 0:
            fn = ida_funcs.get_func(scope_ea)
            if fn == None:
                if ida_funcs.add_func(scope_ea, scope_ea+scope_record.length):
                    fn = ida_funcs.get_func(scope_ea)
                    assert(fn != None)
                else:
                    eprint('Failed to create function at {:04X}:{:04X}'.format(
                        self._image_base // 0x10 + segment_record.code_segment,
                        scope_record.code_offset))
                    
            if fn != None:
                if (fn.end_ea-fn.start_ea) != scope_record.length:
                    if not ida_funcs.set_func_end(scope_ea, scope_ea+scope_record.length):
                        eprint('Failed to set function size at {:04X}:{:04X}'.format(
                            self._image_base // 0x10 + segment_record.code_segment,
                            scope_record.code_offset))
                idc.SetType(scope_ea, '')
                assert(ida_frame.del_frame(fn))

        first_symbol_index = scope_record.symbol_index - 1
        range_end = first_symbol_index + scope_record.symbol_count
        for symbol_index in range(first_symbol_index, range_end):
            symbol = self._parsed_exe.symbol_records[symbol_index]
            self._apply_local_variable(symbol, scope_ea)

    def _apply_local_variable(self, symbol, scope_ea):
        if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.AUTO.name:
            return

        type_record = self._parsed_exe.type_records[symbol.type - 1]
        type_flag, type_index = self._type_record_to_ida_type_flag(symbol.type)
        offset = ctypes.c_int16(symbol.offset).value

        tid = None
        #TODO: IDA doesn't support union type stkvar?
        tt = self._parsed_exe.type_records[type_index-1]
        if tt.id == tdinfo_structs.TypeId.STRUCT.name and type_flag == ida_bytes.stru_flag():
            tid = self._get_struct_tid(type_index)

        symbol_name = self._get_name_from_pool(symbol.index)
        func_ptr = ida_funcs.get_func(scope_ea)

        if ida_frame.define_stkvar(func_ptr, symbol_name, offset, type_flag, tid, type_record.size):
            variable_location_string = '[bp{}{:02X}]'.format(
                '+' if offset >= 0 else '-', abs(offset))
            print('Applied name {} to {} in function {}'.format(
                symbol_name,
                variable_location_string,
                ida_funcs.get_func_name(scope_ea)))

    def apply(self):
        applied_global_symbols_count = 0
        already_existing_global_symbols_count = 0

        for symbol in self._parsed_exe.symbol_records:
            self._name_type(symbol)

        for i in range (0, len(self._parsed_exe.type_records)):
            self._create_struct_union_enum(i)

        for segment_record in self._parsed_exe.segment_records:
            self._apply_segment(segment_record)

        for symbol in self._parsed_exe.symbol_records:
            try:
                if self._is_global_symbol(symbol):
                    self._apply_global_symbol(symbol)
                    applied_global_symbols_count += 1
                elif self._is_type_symbol(symbol):
                    pass
                else:
                    raise TdinfoParserUnsupportedSymbolClassException()
            except TdinfoParserSymbolAlreadyAppliedException:
                already_existing_global_symbols_count += 1
            except TdinfoParserIdaSetNameFailedException:
                pass
            except TdinfoParserUnsupportedSymbolClassException:
                pass

        for segment_record in self._parsed_exe.segment_records:
            self._apply_scopes(segment_record)

        print('Detected {} global symbols.'.format(
            self._parsed_exe.tdinfo_header.globals_count)),
        print('{} identical symbols already existed, {} new symbols were applied.'.format(
            already_existing_global_symbols_count,
            applied_global_symbols_count))

p = TdinfoParser()
p.apply()