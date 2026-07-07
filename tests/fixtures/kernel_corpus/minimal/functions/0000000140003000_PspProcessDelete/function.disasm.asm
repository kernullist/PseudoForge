; PseudoForge full function disassembly
; Function: PspProcessDelete
; EA: 0x140003000
; Range: 0x140003000-0x140003030

0000000140003000  lea rcx, aProcessDelete
0000000140003007  call ObDereferenceObject
000000014000300C  retn
