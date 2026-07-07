; PseudoForge full function disassembly
; Function: NtCreateUserProcess
; EA: 0x140001000
; Range: 0x140001000-0x140001020

0000000140001000  sub rsp, 28h
0000000140001004  call PspAllocateProcess
0000000140001009  add rsp, 28h
000000014000100D  retn
