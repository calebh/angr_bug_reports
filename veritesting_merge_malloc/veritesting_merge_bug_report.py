import angr
import claripy

NULL_PTR = 0x0
INT_SIZE = 4
PTR_SIZE = 8

arg = claripy.BVS('int_arg', PTR_SIZE * 8)

proj = angr.Project('null_deref_patched')
fun_prototype = 'void f(int *a)'
fun_addr = proj.loader.find_symbol("my_fun").rebased_addr

state = proj.factory.call_state(fun_addr, arg, prototype=fun_prototype,
                                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                             angr.options.SYMBOLIC_WRITE_ADDRESSES})
state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())

# The following two lines are unnecessary to trigger the error, however this
# is how our original example was triggered.
#concrete_addr = state.heap.malloc(INT_SIZE)
#state.add_constraints((arg == NULL_PTR) | (arg == concrete_addr))

simgr = proj.factory.simulation_manager(state, veritesting=True) # Disable veritesting and everything works okay
simgr.run()
