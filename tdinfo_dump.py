import tdinfo_structs
from io import StringIO
import sys
import ctypes
import argparse

TDINFO_MEMBER_INFO_END_MARKER = 0xC0
TDINFO_MEMBER_PADDING_MARKER = 0x40
REGISTER_NAME = ['AX', 'BX', 'CX', 'DX', 'SP', 'BP', 'SI', 'DI']
PASCAL = 5

class TdinfoDump(object):
    def __init__(self, input_file_path, context):
        self._parsed_exe = tdinfo_structs.DOS_MZ_EXE_STRUCT.parse_file(input_file_path)
        self._context = context

        print('/*Borland TLink symbolic information version: {}.{:02}*/'.format(
            self._parsed_exe.tdinfo_header.major_version,
            self._parsed_exe.tdinfo_header.minor_version))

        self._dumped_struct_union_enum = set()

    def _get_name_from_pool(self, name_index):
        if name_index == 0:
            return None
        return str(self._parsed_exe.name_pool[name_index - 1])
    
    def _add_fake_name_to_pool(self, name):
        self._parsed_exe.name_pool.append(name)
        return len(self._parsed_exe.name_pool)

    def _get_cdecl(self, type, r):
        if type.id == tdinfo_structs.TypeId.VOID.name:
            return 'void', type.size
        if type.id == tdinfo_structs.TypeId.LSTR.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.DSTR.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.PSTR.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.SCHAR.name:
            return 'signed char', type.size
        if type.id == tdinfo_structs.TypeId.SINT.name:
            return 'int', type.size
        if type.id == tdinfo_structs.TypeId.SLONG.name:
            return 'long', type.size
        if type.id == tdinfo_structs.TypeId.UCHAR.name:
            return 'unsigned char', type.size
        if type.id == tdinfo_structs.TypeId.UINT.name:
            return 'unsigned int', type.size
        if type.id == tdinfo_structs.TypeId.ULONG.name:
            return 'unsigned long', type.size
        if type.id == tdinfo_structs.TypeId.PCHAR.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.FLOAT.name:
            return 'float', type.size
        if type.id == tdinfo_structs.TypeId.TPREAL.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.DOUBLE.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.LDOUBLE.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.BCD4.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.BCD8.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.BCD10.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.BCDCOB.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.NEAR.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.FAR.name:
            t, size = self._get_cdecl(self._parsed_exe.type_records[type.member_type - 1], r+1)
            return t+'*', type.size
        if type.id == tdinfo_structs.TypeId.SEG.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.NEAR386.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.FAR386.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.ARRAY.name:
            t, size = self._get_cdecl(self._parsed_exe.type_records[type.member_type - 1], r+1)
            assert(type.size % size == 0)
            return t+f'[{int(type.size/size)}]', type.size
        if type.id == tdinfo_structs.TypeId.PARRAY.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.STRUCT.name:
            return 'struct ' + self._get_name_from_pool(type.name), type.size
        if type.id == tdinfo_structs.TypeId.UNION.name:
            return 'union ' + self._get_name_from_pool(type.name), type.size
        if type.id == tdinfo_structs.TypeId.ENUM.name:
            return 'enum ' + self._get_name_from_pool(type.name), type.size
        if type.id == tdinfo_structs.TypeId.FUNCTION.name:
            t, size = self._get_cdecl(self._parsed_exe.type_records[type.member_type - 1], r+1)
            #function pointer
            if r != 0:
                t = t+' ('
            if type.class_type == 7: #interrupt
                if r != 0: t = t+'interrupt'
                else: t = t+' interrupt'
            return t, type.size
        if type.id == tdinfo_structs.TypeId.LABEL.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.SET.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.TFILE.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.BFILE.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.BOOL.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.PENUM.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.FUNCPROTOTYPE.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.SPECIALFUNC.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.OBJECT.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.NREF.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.FREF.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.WORDBOOL.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.LONGBOOL.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.GLOBALHANDLE.name:
            assert(False)
        if type.id == tdinfo_structs.TypeId.LOCALHANDLE.name:
            assert(False)

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

    def _dump_member_type(self, index):
        type_record = self._parsed_exe.type_records[index - 1]
        type_id = type_record.id
        if type_id == tdinfo_structs.TypeId.NEAR.name or \
            type_id == tdinfo_structs.TypeId.FAR.name or \
            type_id == tdinfo_structs.TypeId.ARRAY.name:
            self._dump_member_type(type_record.member_type)
        elif type_id == tdinfo_structs.TypeId.STRUCT.name or \
            type_id == tdinfo_structs.TypeId.UNION.name or \
            type_id == tdinfo_structs.TypeId.ENUM.name:
            self._dump_struct_union_enum(index - 1)
    
    def _dump_struct_union_enum(self, i):
        type_record = self._parsed_exe.type_records[i]

        if type_record.id != tdinfo_structs.TypeId.STRUCT.name and \
           type_record.id != tdinfo_structs.TypeId.UNION.name and \
           type_record.id != tdinfo_structs.TypeId.ENUM.name:
            return
        
        if i in self._dumped_struct_union_enum:
            return

        assert(type_record.class_type == 0)
        
        union = False
        struct = False
        name = self._get_name_from_pool(type_record.name)
        total_size = 0
        text_stream = StringIO()

        if type_record.id == tdinfo_structs.TypeId.STRUCT.name:
            if name is None:
                name = 'struct_' + str(i)
                type_record.name = self._add_fake_name_to_pool(name)
            text_stream.write('//size: ' + str(type_record.size) + '\n')
            text_stream.write('struct ' + name + ' {\n')
            struct = True
        elif type_record.id == tdinfo_structs.TypeId.UNION.name:
            if name is None:
                name = 'union_' + str(i)
                type_record.name = self._add_fake_name_to_pool(name)
            text_stream.write('//size: ' + str(type_record.size) + '\n')
            text_stream.write('union ' + name + ' {\n')
            union = True
        elif type_record.id == tdinfo_structs.TypeId.ENUM.name:
            if name is None:
                name = 'enum_' + str(i)
                type_record.name = self._add_fake_name_to_pool(name)
            text_stream.write('enum ' + name + ' {\n')

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
            self._dump_member_type(member.type)
            decl, size = self._get_cdecl(member_type, 0)
            assert(member_type.class_type == 0)

            text_stream.write('\t//offset: ' + (str(offset)) + ' (' + str(size) + ' bytes)\n')
            if '[' in decl:
                s = decl.split('[')
                s.reverse()
                text_stream.write('\t' + s[-1] + ' ' + member_name + '[' + '['.join(s[0:-1]) + ';\n')
            elif '(' in decl:
                text_stream.write('\t' + decl + ' ' + member_name + ')(void);\n')
            else:
                text_stream.write('\t' + decl + ' ' + member_name + ';\n')

            if union:
                if size > total_size:
                    total_size = size
            elif struct:
                total_size += size
                offset += size

        text_stream.write('};\n')
        text_stream.seek(0)
        print(text_stream.read())
        self._dumped_struct_union_enum.add(i)

        if union or struct:
            total_size = (total_size + 1) & ~1
            assert(total_size == type_record.size)

    def _dump_typedef(self, symbol):
        if not symbol.type:
            return

        symbol_class = symbol.bitfield.symbol_class
        if symbol_class != tdinfo_structs.SymbolClass.TYPEDEF.name:
            return

        type_record = self._parsed_exe.type_records[symbol.type - 1]
        decl, size = self._get_cdecl(type_record, 0)
        assert(type_record.class_type == 0)
        name = self._get_name_from_pool(symbol.index)
        assert(name is not None)
        assert('[' not in decl and '(' not in decl)
        print('typedef ' + decl + ' ' + name + ';')

    def _dump_variable(self, symbol):        
        symbol_class = symbol.bitfield.symbol_class
        if symbol_class in [tdinfo_structs.SymbolClass.STRUCT_UNION_OR_ENUM.name,
                            tdinfo_structs.SymbolClass.TYPEDEF.name,
                            tdinfo_structs.SymbolClass.AUTO.name,
                            tdinfo_structs.SymbolClass.REGISTER.name]:
            return

        if symbol.type != 0:
            type_record = self._parsed_exe.type_records[symbol.type - 1]
            if type_record.id == tdinfo_structs.TypeId.FUNCTION.name:
                return
            decl, size = self._get_cdecl(type_record, 0)
            assert(type_record.class_type == 0)
            assert(type_record.size == size)
        else:
            #ASM symbols
            return

        name = self._get_name_from_pool(symbol.index)
        name = name[1:] #skip leading underscore

        print('//addr: ' + (f'{symbol.segment:04X}' + ':' + f'{symbol.offset:04X}'))
        print('//size: ' + (str(type_record.size)))
        assert(symbol_class == tdinfo_structs.SymbolClass.STATIC.name)

        if '[' in decl:
            s = decl.split('[')
            s.reverse()
            print('extern ' + s[-1] + ' ' + name + '[' + '['.join(s[0:-1]) + ';\n')
        elif '(' in decl:
            print('extern ' + decl + ' ' + name + ')(void);\n')
        else:
            print('extern ' + decl + ' ' + name + ';\n')

    def _visit_scopes(self, segment_record, symbols):
        first_scope_index = segment_record.scope_index - 1
        range_end = first_scope_index + segment_record.scope_count
        for scope_index in range(first_scope_index, range_end):
            scope_record = self._parsed_exe.scope_records[scope_index]
            self._dump_function(segment_record, scope_record, symbols)

    def _dump_function(self, segment_record, scope_record, symbols):
        module = self._parsed_exe.module_records[segment_record.module - 1]
        module_name = self._get_name_from_pool(module.name)

        if scope_record.parent == 0:
            print('//module: ' + module_name)
            print('//size: ' + hex(scope_record.length))
            print('//addr: ' + (f'{segment_record.code_segment:04X}' + ':' + f'{scope_record.offset:04X}'))
            addr = (segment_record.code_segment << 16) + scope_record.offset
            func = symbols[addr]
            type_record = self._parsed_exe.type_records[func.type - 1]
            assert(type_record.id == tdinfo_structs.TypeId.FUNCTION.name)
            assert(func.bitfield.symbol_class == tdinfo_structs.SymbolClass.STATIC.name)

            name = self._get_name_from_pool(func.index)
            if type_record.class_type != PASCAL:
                name = name[1:] #skip leading underscore
            assert(func.type > 0)

            decl, size = self._get_cdecl(type_record, 0)
            assert('[' not in decl and '(' not in decl)
            assert(size == 0)

            if type_record.class_type != PASCAL:
                print(decl + ' ' + name + '(', end='')
            else:
                print(decl + ' pascal ' + name + '(', end='')

            first_symbol_index = scope_record.symbol_index - 1
            range_end = first_symbol_index + scope_record.symbol_count

            if scope_record.symbol_count != 0:
                prev_offset = 0
                for symbol_index in range(range_end-1, first_symbol_index-1, -1):
                    symbol = self._parsed_exe.symbol_records[symbol_index]
                    offset = ctypes.c_int16(symbol.offset).value
                    assert(offset >= 6)
                    #TODO: check pascal stack order
                    if type_record.class_type != PASCAL:
                        assert(prev_offset < offset)
                    self._dump_function_args(symbol)
                    prev_offset = offset
                    if symbol_index != first_symbol_index:
                        print(', ', end='')
            else:
                print('void', end='')

            if self._context:
                print(');')
            else:
                print(')')
        else:
            if self._context:
                return
            #scope_offset = self._parsed_exe.scope_records[scope_record.parent - 1].offset
            parent_scope_record = self._parsed_exe.scope_records[scope_record.parent - 1]
            addr = (segment_record.code_segment << 16) + parent_scope_record.offset
            func = symbols[addr]
            parent_type_record = self._parsed_exe.type_records[func.type - 1]
        
            first_symbol_index = scope_record.symbol_index - 1
            range_end = first_symbol_index + scope_record.symbol_count

            print('{')
            prev_offset = sys.maxsize
            for symbol_index in range(range_end-1, first_symbol_index-1, -1):
                symbol = self._parsed_exe.symbol_records[symbol_index]
                offset = ctypes.c_int16(symbol.offset).value
                if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.REGISTER.name:
                    #TODO: check pascal stack order
                    if parent_type_record.class_type != PASCAL:
                        assert(prev_offset > offset)
                    prev_offset = offset
                self._dump_local_variable(symbol)
            print('}\n')

    def _dump_function_args(self, symbol):
        assert(symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.AUTO.name)
        type_record = self._parsed_exe.type_records[symbol.type - 1]
        name = self._get_name_from_pool(symbol.index)
        decl, size = self._get_cdecl(type_record, 0)
        assert(type_record.class_type == 0)
        assert('[' not in decl and '(' not in decl)
        print(decl + ' ' + name, end='')

    def _dump_local_variable(self, symbol):
        assert(symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.AUTO.name or \
               symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.REGISTER.name )
        
        offset = ctypes.c_int16(symbol.offset).value
        if symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.AUTO.name and offset >= 6:
            return
        
        type_record = self._parsed_exe.type_records[symbol.type - 1]
        name = self._get_name_from_pool(symbol.index)
        decl, size = self._get_cdecl(type_record, 0)
        assert(type_record.class_type == 0)

        if symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.AUTO.name:
            assert(offset < 0)
            print(f'\t//stack: [BP-{abs(offset)}]')
        else:
            print('\t//register: ' + REGISTER_NAME[offset])
        print('\t//size: ' + (str(type_record.size)))
        if '[' in decl:
            s = decl.split('[')
            s.reverse()
            print('\t' + s[-1] + ' ' + name + '[' + '['.join(s[0:-1]) + ';')
        elif '(' in decl:
            print('\t' + decl + ' ' + name + ')(void);')
        else:
            print('\t' + decl + ' ' + name + ';')

        
    def dump(self):
        for symbol in self._parsed_exe.symbol_records:
            self._name_type(symbol)

        for i in range(0, len(self._parsed_exe.type_records)):
            self._dump_struct_union_enum(i)

        for symbol in self._parsed_exe.symbol_records:
            self._dump_typedef(symbol)
        print()

        for symbol in self._parsed_exe.symbol_records:
            self._dump_variable(symbol)

        symbols = {}
        for symbol in self._parsed_exe.symbol_records:
            addr = (symbol.segment << 16) + symbol.offset
            symbols[addr] = symbol

        #TODO: line number?
        for segment_record in self._parsed_exe.segment_records:
            self._visit_scopes(segment_record, symbols)

parser = argparse.ArgumentParser(prog='python tdinfo_dump.py')
parser.add_argument('DOS_MZ_EXE', nargs='?', default=None)
parser.add_argument('-c', '--context', action='store_true', default=False, help='Dump functions prototype only')
args = parser.parse_args()

if args.DOS_MZ_EXE == None:
    parser.print_help()

p = TdinfoDump(args.DOS_MZ_EXE, args.context)
p.dump()