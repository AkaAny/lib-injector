;;x0存的是libpath，x1存的是RTLD_NOW，x2存的是dlopen，x3存的是pthread_create_from_mach_thread
;;32是4个寄存器的栈，16是原本分配出去的
;; as shellcode.asm -o shellcode.o && ld ./shellcode.o -o shellcode -lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path`

.global _main
 .align 4
 _main:
         mov x0, sp
         sub x0, x0, #16
         mov x1, xzr
         mov x3, xzr
         adr x4, pthrdcrt
         adr x2, _thread
         ldr x5, [x4]
         blr x5
 _loop:
         adr x7, _loop
         br x7
 pthrdcrt: .ascii "PTHRDCRT"
 dlllopen: .ascii "DLOPEN__"
 _thread:
         mov x1, #1
         adr x0, lib
         adr x7, dlllopen
         ldr x8, [x7]
         blr x8
 _thread_loop:
         adr x7, _thread_loop
         br x7

 lib: .ascii "LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"