# Sanctum

This is simple project that uses qiling framework to emulate a binary, a custom class to taint data and record operations on it, and triton to build the ast and simplify it. 
The project have very good performance and can be used to analyze big obfuscated binaries.
Only few instructions are supported, but it's easy to add new ones.

To see how it works, you can consult the example in the `example` folder.
Qiling use rootfs to emulate the binary, so you need to create a rootfs for your binary or use the one provided in the qiling `rootfs` project folder. To create a new rootfs, you can use https://github.com/matrix1001/glibc-all-in-one and get a glibc that match your binary architecture, create a folder and copy inside the lib directory the glic you want to use.

To install triton, you can use the following instructions:
```bash
install captsone and cd capstone-4.0.2/ && ./make.sh install 
install llvm (apt-get install llvm)
cmake -DLLVM_INTERFACE=ON  ...  && sudo make install
pip install triton-library

```
