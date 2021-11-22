import string

import miasm.jitter.jitload
from miasm.jitter.csts import PAGE_EXEC, PAGE_READ, PAGE_WRITE, EXCEPT_SYSCALL, EXCEPT_BREAKPOINT_MEMORY
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
FLAG_BASE = 0x0
CHR_OFF = None
FLAG_CH=""

def handlesys(jit: miasm.jitter.jitload.Jitter):
    global FLAG_BASE,trychar
    sysno = jit.cpu.EAX
    # print(sysno)
    if sysno == 0:
        FLAG_BASE = jit.cpu.RSI
        jit.vm.add_memory_breakpoint(FLAG_BASE, jit.cpu.RDX, PAGE_READ)
        jit.vm.set_mem(FLAG_BASE, b'\x00'*jit.cpu.RDX)
    jit.cpu.set_exception(0)
    return True


def handlemem(jit: miasm.jitter.jitload.Jitter):
    global FLAG_BASE, CHR_OFF,FLAG_CH
    # read the flag
    FLAG_CH=chr(jit.cpu.RAX)
    s, _ = jit.vm.get_memory_read()[0]
    CHR_OFF = s - FLAG_BASE
    jit.vm.set_exception(0)
    jit.vm.reset_memory_access()
    return False

emucode=bytes.fromhex(input()) if 1 else bytes.fromhex(open("sc.bad","r").read())
def solve():
    myjit = Machine("x86_64").jitter(LocationDB(), "llvm")
    myjit.init_stack()
    run_addr = 0x400000
    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE | PAGE_EXEC, emucode)
    myjit.vm.reset_memory_access()
    #myjit.jit.set_options(jit_maxline=1, max_exec_per_call=1)
    #myjit.exec_cb = handleinstr
    myjit.exceptions_handler.callbacks[EXCEPT_BREAKPOINT_MEMORY] = []
    myjit.add_exception_handler(EXCEPT_SYSCALL, handlesys)
    myjit.add_exception_handler(EXCEPT_BREAKPOINT_MEMORY, handlemem)
    #myjit.set_trace_log()
    myjit.init_run(run_addr)
    try:
        myjit.continue_run()
    except Exception as e:
        #print(emucode.hex())
        assert (False)
solve()
assert(CHR_OFF!=None)
print(FLAG_CH,CHR_OFF)
