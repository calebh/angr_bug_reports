import angr
import sys

proj = angr.Project('strtok_r_bug')
fun_prototype = 'int main()'
fun_addr = proj.loader.find_symbol("main").rebased_addr

state = proj.factory.call_state(fun_addr, prototype=fun_prototype,
                                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                                             angr.options.SYMBOLIC_WRITE_ADDRESSES})

state.libc.simple_strtok = False

simgr = proj.factory.simulation_manager(state)
simgr.run()

stdout_fileno = sys.stdout.fileno()
print(simgr.deadended[0].posix.dumps(stdout_fileno))
