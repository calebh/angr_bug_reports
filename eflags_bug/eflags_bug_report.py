import angr
import claripy

INT_SIZE = 4

arg0 = [5, 4, 3]
arg1 = claripy.BVS('idx_arg', INT_SIZE * 8)
args = [arg0, arg1]

proj = angr.Project('buff_overflow_patched')
fun_prototype = 'int patch_fun(int a[], int i)'
fun_addr = proj.loader.find_symbol("patch_fun").rebased_addr

state = proj.factory.call_state(fun_addr, *args, prototype=fun_prototype,
                                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                             angr.options.SYMBOLIC_WRITE_ADDRESSES})

simgr = proj.factory.simulation_manager(state, veritesting=True) # Disable veritesting and everything works okay
simgr.run()

for st in simgr.deadended:
    print("eflags", st.regs.eflags)