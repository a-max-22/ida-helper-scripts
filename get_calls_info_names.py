import ida_idaapi
import idaapi
import ida_hexrays
import ida_funcs
import ida_frame
import ida_struct
#search for switch case with specific value

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
                    print("desired value found")                         
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
                        print(local_var_id)
                        params.append('LOC ' + local_var_id)                                        
                    except AttributeError:
                        continue                                            
                    
                    continue
                    
                if func_arg.op == idaapi.cot_num:
                    params.append('C ' + str(func_arg.numval()))
            
            self.result.append(func_name)
            self.result.append(params)
            print(self.result)

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
                print(labels[0])
                self.result[labels[0]] = call_info
                
        return 0

  
    def get_result(self):
        return self.result                



f = idaapi.get_func(idaapi.get_name_ea(0,"main"))
cfunc = idaapi.decompile(f)

cv = case_searcher(0xA3)
cv.apply_to(cfunc.body, None)
needed_case = cv.get_found_case()

cc = case_func_calls_enumerator()
cc.apply_to(needed_case, None)

calls_info = cc.get_result()
print(calls_info)
