[binaries]
c = 'clang'
ar = 'ar'

[host_machine]
system = 'darwin'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'

[properties]
c_args = ['-arch', 'arm64']
needs_exe_wrapper = true


