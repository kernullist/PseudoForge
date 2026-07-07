; PseudoForge full function disassembly
; Function: PspAllocateProcess
; EA: 0x140002000
; Range: 0x140002000-0x140002030

0000000140002000  mov rcx, cs:PsProcessType
0000000140002007  call ExAllocatePool2
000000014000200C  mov [rax+2E0h], rcx
0000000140002013  retn
