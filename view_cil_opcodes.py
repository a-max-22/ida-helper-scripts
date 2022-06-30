#decode opcodes from each switch statement
#can we do it authomatically?
import ida_idaapi
import idaapi
import ida_hexrays
import ida_funcs
import ida_frame
import ida_struct
    

# instr[opcode] = {opnd_size, display_func}
instructions_set = {}

instructions_set[0x5A] = (0, lambda opnd:'RET')
instructions_set[0x5B] = (4, lambda opnd:'PUSH LOCAL '+hex(opnd))
instructions_set[0x64] = (0, lambda opnd:'LOAD DWORD')
instructions_set[0x67] = (4, lambda opnd:'PUSH DWORD '+hex(opnd))
instructions_set[0x7B] = (0, lambda opnd:'ADD')
instructions_set[0x84] = (0, lambda opnd:'MUL')
instructions_set[0x88] = (4, lambda opnd:'PUSH stream '+hex(opnd))

instructions_set[0x1] = (4, lambda opnd:'JMP '+hex(opnd+1))
instructions_set[0x3] = (0, lambda opnd:'ADD DWORD')
instructions_set[0x7] = (0, lambda opnd:'ADD QWORD')

instructions_set[0x12] = (0, lambda opnd:'DEREF BYTE PTR')
instructions_set[0x13] = (4, lambda opnd:'PUSH STRING PTR '+hex(opnd))
instructions_set[0x18] = (0, lambda opnd:'DEREF DWORD PTR')
instructions_set[0x23] = (0, lambda opnd:'DEREF DWORD PTR')

instructions_set[0x2A] = (0, lambda opnd:'DEREF PPSTR')
instructions_set[0x3A] = (0, lambda opnd:'LOAD QWORD')

instructions_set[0x9A] = (8, lambda opnd:'PUSH QWORD '+hex(opnd))

#instructions_set[0xA3] = (4, lambda opnd:'CALL '+ hex(opnd))
instructions_set[0xA8] = (0, lambda opnd:'DEREF QWORD PTR ')
instructions_set[0xB6] = (0, lambda opnd:'IS GREATER THAN')
instructions_set[0xBE] = (8, lambda opnd:'PUSH QWORD ' + hex(opnd))
instructions_set[0xBF] = (4, lambda opnd:'PUSH INT '+ hex(opnd))
instructions_set[0xC5] = (0, lambda opnd:'SUB')
instructions_set[0xF5] = (0, lambda opnd:'IS LESS THAN')
instructions_set[0xF7] = (0, lambda opnd:'NOP')
instructions_set[0xFA] = (4, lambda opnd:'JNZ '+hex(opnd+1))
instructions_set[0xFC] = (0, lambda opnd:'DEREF PTR TO PTR TO DWORD')
instructions_set[0xFD] = (0, lambda opnd:'ARE VALUES EQUAL')
instructions_set[0xFE] = (0, lambda opnd:'DEREF BYTE')


class case_searcher(idaapi.ctree_visitor_t):    
    def __init__(self, value_to_search=0x00):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.value_to_search = value_to_search
        self.found_case = None
    
    def visit_insn(self,i):
        if i.op == idaapi.cit_switch:
            for c in i.cswitch.cases:
                labels = [ l for l in c.values ]
                if len(labels) == 1 and labels[0] == self.value_to_search:
                    self.found_case = c.cinsn 
                    #print("desired value found")                         
        return 0
    
    def visit_expr(self, e):
        return 0

    def get_found_case(self):
        return self.found_case


#gets info on first called function in the block
class block_functions_enumerator(idaapi.ctree_visitor_t):
    def __init__(self):         
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.result = []
                
    def visit_expr(self, e):
        if e.op == idaapi.cot_call:
            func_name = ida_funcs.get_func_name(e.x.obj_ea)
            func_name = func_name.replace('.','')
            
            parent_func = ida_funcs.get_func(e.ea)                        
            parent_func_dec = idaapi.decompile(parent_func)
            parent_frame = ida_frame.get_frame(e.ea)
    
            params = []
            
            for func_arg in e.a:
                if func_arg.op == idaapi.cot_var:
                    #offset of original local vars array is 0x100 from stackPtr named variable
                    virtual_stack_ptr = ida_struct.get_member_by_name(parent_frame, 'stackPtr')                                        
                    current_var_ptr   = ida_struct.get_member_by_name(parent_frame, parent_func_dec.lvars[func_arg.v.idx].name)
                    
                    try:
                        local_var_id = hex(current_var_ptr.soff  - virtual_stack_ptr.soff - 0x100)
                        params.append('LOCAL ' + local_var_id)                                        
                    except AttributeError:
                        continue                                            
                    
                    continue
                    
                if func_arg.op == idaapi.cot_num:
                    params.append('C ' + str(func_arg.numval()))
            
            self.result.append(func_name)
            self.result.append(params)

            return 1
            
        return 0
               
    def get_call_info(self):
        return self.result
     


class case_func_calls_enumerator(idaapi.ctree_visitor_t):
    def __init__(self):         
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.result = {}        

    def visit_insn(self,i):
        if i.op == idaapi.cit_switch:
            for c in i.cswitch.cases:
                labels = [ l for l in c.values ]
                if len(labels) > 1 or len(labels) == 0:
                    print("more than one label found for case or no label found", labels)
                    continue                    
                fe = block_functions_enumerator()
                fe.apply_to(c.cinsn, None)
                
                call_info = fe.get_call_info()
                #print(labels[0])
                self.result[labels[0]] = call_info                
        return 0
  
    def get_result(self):
        return self.result                


def make_instr_list(instr_ea, inst_set):
    instr_list = []
    opcode = 0x00
    opcode_size = 1
    
    cur_ea = instr_ea
    
    while True:
        opcode = idaapi.get_bytes(cur_ea, 1)
        
        try:
            inst = inst_set[ord(opcode)]
            opnd_size = inst[0]
            
            opnd = None
            if (opnd_size == 4):
                opnd = idaapi.get_dword(cur_ea + opcode_size)
            if (opnd_size == 8):
                opnd = idaapi.get_qword(cur_ea + opcode_size)            
            
            instr_display_func = inst[1]
            
            instr_pos = cur_ea - instr_ea
            #handle control flow instructions JMP or JNZ
            if ord(opcode) == 0xFA or ord(opcode) == 0x01:
                opnd += instr_pos
                opnd &= 0xFFFFFFFF
                
            print('         :' + hex(instr_pos) + ': ' + instr_display_func(opnd))
            '''
            if (opnd_size > 0):
                print(inst[1]+','+hex(opnd))
            else:
                print(inst[1])
            '''
                
            cur_ea = cur_ea + opnd_size + opcode_size            
            
        except KeyError:
            print("Unknown opcode", opcode)
            break    
    
    return instr_list


f = idaapi.get_func(idaapi.get_name_ea(0,"main"))
cfunc = idaapi.decompile(f)

cv = case_searcher(0xA3)
cv.apply_to(cfunc.body, None)
needed_case = cv.get_found_case()

cc = case_func_calls_enumerator()
cc.apply_to(needed_case, None)
calls_info = cc.get_result()

#print(calls_info)
def make_call_info(call_index):
    try: 
        call_info = calls_info[call_index]
        result = 'CALL '
        result = result + call_info[0] + '('
        for arg in call_info[1]:
            result = result + arg + ','
        result += ')'
        
        return result     
    except KeyError:
        print("make_call_info: unknown call index "+hex(call_index))

instructions_set[0xA3] = (4, make_call_info)


main_array_ea = idaapi.get_name_ea(0,"_1_main_$array")        
instr_list = make_instr_list(main_array_ea, instructions_set)