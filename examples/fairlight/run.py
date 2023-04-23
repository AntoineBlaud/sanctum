
from sanctum import *
from qiling import *


if __name__ == "__main__":
    
    ql = Qiling(["examples/fairlight/fairlight", "secret_valueBB"], r"/opt/qiling/examples/rootfs/x8664_linux")
    debug_level = DebugLevel.FUNC_SYMDATA
    sanctum = Sanctum(ql, debug_level=debug_level)
    addr = 0x6030B8
    expected_value = "secret_valueBB".encode()
    sanctum.hook_address(addr ,bytearray(expected_value) , "in[%d]")
    sanctum.run()
   

# https://github.com/matrix1001/glibc-all-in-one
# installer des nouvelles rootfs 
# Faire tigress