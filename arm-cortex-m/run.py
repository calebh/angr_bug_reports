import angr

proj = angr.Project("test.o")

def run_fun(name, expected_primask):
    print("RUNNING FUNCTION {}".format(name))
    fun_addr = proj.loader.find_symbol(name).rebased_addr
    state = proj.factory.call_state(fun_addr, prototype="void f()")

    print("primask before", state.regs.primask)

    simgr = proj.factory.simgr(state)
    while len(simgr.active) > 0:
        simgr.step()

    for deadended_state in simgr.deadended:
        print("primask after", deadended_state.regs.primask)
        if deadended_state.regs.primask.concrete_value != expected_primask:
            print("TEST FAILED!")
        else:
            print("TEST PASSED")

    print("\n\n")

run_fun("test", 1)
run_fun("test2", 1)
run_fun("test3", 0)
run_fun("test4", 0)