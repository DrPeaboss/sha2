// This file is part of sha2.pas
// Sha512 x86_64 asm for optimization   
procedure SHA512Compress(var Context:TSHA512Context);assembler;
const
  PK512:Pointer = @K512;
var
  W:Array[0..79] of UInt64;
asm
  push rbx
  push r12
  push r14
  push r15
{$ifdef MSWINDOWS}
  push rdi
  push rsi
  mov r15, rcx  // save the context
{$endif}
{$ifdef LINUX}
  mov r15, rdi  // save the context
{$endif}
  mov rax, PK512  // must use rax
  mov r14, rax
  // swap
  mov rdi, [r15+64] // W[0]
  bswap rdi
  mov qword ptr W[0], rdi
  mov rax, [r15+72]
  bswap rax
  mov qword ptr W[8], rax
  mov rax, [r15+80]
  bswap rax
  mov qword ptr W[16], rax
  mov rax, [r15+88]
  bswap rax
  mov qword ptr W[24], rax
  mov rax, [r15+96]
  bswap rax
  mov qword ptr W[32], rax
  mov rax, [r15+104]
  bswap rax
  mov qword ptr W[40], rax
  mov rax, [r15+112]
  bswap rax
  mov qword ptr W[48], rax
  mov rax, [r15+120]
  bswap rax
  mov qword ptr W[56], rax
  mov rax, [r15+128]
  bswap rax
  mov qword ptr W[64], rax
  mov rax, [r15+136]
  bswap rax
  mov qword ptr W[72], rax
  mov rax, [r15+144]
  bswap rax
  mov qword ptr W[80], rax
  mov rax, [r15+152]
  bswap rax
  mov qword ptr W[88], rax
  mov rax, [r15+160]
  bswap rax
  mov qword ptr W[96], rax
  mov rax, [r15+168]
  bswap rax
  mov qword ptr W[104], rax
  mov rsi, [r15+176] // W[14]
  bswap rsi
  mov qword ptr W[112], rsi
  mov r8, [r15+184]  // W[15]
  bswap r8
  mov qword ptr W[120], r8

  //i:=16;
  //repeat
  //  W[i] := LowerSigma1_512(W[i-2])+W[i-7]+LowerSigma0_512(W[i-15])+W[i-16];
  //  W[i+1]:=LowerSigma1_512(W[i-1])+W[i-6]+LowerSigma0_512(W[i-14])+W[i-15];
  //  Inc(i,2);
  //until i = 80;
  mov rcx, 16
@L1:
  // LowerSigma1_512(W[i-2])
  mov rax, rsi  // rsi = W[i-2]
  mov rdx, rax
  shr rax, 6
  ror rdx, 19
  xor rax, rdx
  ror rdx, 42
  xor rax, rdx
  mov rsi, rax
  add rsi, qword ptr W[rcx*8-56] // @W[i-7]
  add rsi, rdi // rdi = W[i-16]
  // LowerSigma0_512(W[i-15])
  mov rax, qword ptr W[rcx*8-120]
  mov rbx, rax // rbx = W[i-15]
  mov rdx, rax
  shr rax, 7
  ror rdx, 1
  xor rax, rdx
  ror rdx, 7
  xor rax, rdx
  add rsi, rax // rsi = W[i-2]
  // W[i] := ...
  mov qword ptr W[rcx*8], rsi
  // LowerSigma1_512(W[i-1])
  mov rax, r8  // r8 = W[i-1]
  mov rdx, rax
  shr rax, 6
  ror rdx, 19
  xor rax, rdx
  ror rdx, 42
  xor rax, rdx
  mov r8, rax
  add r8, qword ptr W[rcx*8-48] // W[i-6]
  add r8, rbx // rbx = W[i-15]
  // LowerSigma0_512(W[i-14])
  mov rax, qword ptr W[rcx*8-112]
  mov rdi, rax  // rdi = W[i-14], next loop's W[i-16]
  mov rdx, rax
  shr rax, 7
  ror rdx, 1
  xor rax, rdx
  ror rdx, 7
  xor rax, rdx
  add r8, rax // r8 = W[i-1]
  // W[i+1] := ...
  mov qword ptr W[rcx*8+8], r8
  add rcx, 2
  cmp rcx, 80
  jne @L1

  //A:=Context.H[0];
  //B:=Context.H[1];
  //C:=Context.H[2];
  //D:=Context.H[3];
  //E:=Context.H[4];
  //F:=Context.H[5];
  //G:=Context.H[6];
  //H:=Context.H[7];
  mov rax, [r15]    // A
  mov rbx, [r15+8]  // B
  mov rcx, [r15+16] // C
  mov rdx, [r15+24] // D
  mov rdi, [r15+32] // E
  mov rsi, [r15+40] // F
  mov r8, [r15+48]  // G
  mov r9, [r15+56]  // H

  //i:=0;
  //repeat
  //  T:=H+K512[i]+W[i];
  //  H:=G;
  //  T:=T+Ch(E,F,G);
  //  G:=F;
  //  F:=E;
  //  T:=T+UpperSigma1(E);
  //  E:=D+T;
  //  T:=T+UpperSigma0(A)+Maj(A,B,C);
  //  D:=C;
  //  C:=B;
  //  B:=A;
  //  A:=T;
  //  Inc(i);
  //until i = 80;
  xor r10, r10
@L2:
  // T:=W[i]+K512[i]+H
  mov r11, qword ptr W[r10*8]
  add r11, qword ptr [r14+r10*8]
  add r11, r9
  // H:=G
  mov r9, r8
  // T:=T+Ch(E,F,G) // Ch = G xor (E and (F xor G))
  xor r8, rsi   // xor F
  and r8, rdi   // and E
  xor r8, r9    // xor G
  add r11, r8
  // G:=F
  mov r8, rsi
  // F:=E
  mov rsi, rdi
  // T:=T+UpperSigma1_512(E) = ROTR(X,14) xor ROTR(X,18) xor ROTR(X,41)
  mov r12, rdi
  ror rdi, 41
  ror r12, 14
  xor rdi, r12
  ror r12, 4
  xor rdi, r12
  add r11, rdi
  // E:=D+T
  mov rdi, rdx
  add rdi, r11
  // T:=T+UpperSigma0_512(A)+Maj(A,B,C)
  // UpperSigma0_512(A) = ROTR(X,28) xor ROTR(X,34) xor ROTR(X,39)
  mov rdx, rax
  mov r12, rax
  ror rdx, 28
  ror r12, 34
  xor rdx, r12
  ror r12, 5
  xor rdx, r12
  add r11, rdx
  // Maj(A,B,C) = (A and B) or (C and (A or B))
  mov rdx, rax
  mov r12, rax
  or rdx, rbx
  and rdx, rcx
  and r12, rbx
  or rdx, r12
  add r11, rdx
  // D:=C
  mov rdx, rcx
  // C:=B
  mov rcx, rbx
  // B:=A
  mov rbx, rax
  // A:=T
  mov rax, r11
  // Loop
  inc r10
  cmp r10, 80
  jl @L2

  //Inc(Context.H[0],A);
  //Inc(Context.H[1],B);
  //Inc(Context.H[2],C);
  //Inc(Context.H[3],D);
  //Inc(Context.H[4],E);
  //Inc(Context.H[5],F);
  //Inc(Context.H[6],G);
  //Inc(Context.H[7],H);
  //Inc(Context.MsgLen,128);
  add [r15], rax
  add [r15+8], rbx
  add [r15+16], rcx
  add [r15+24], rdx
  add [r15+32], rdi
  add [r15+40], rsi
  add [r15+48], r8
  add [r15+56], r9
  //Inc(Context.MsgLen,128);
  add qword ptr [r15+200], 128

{$ifdef MSWINDOWS}
  pop rsi
  pop rdi
{$endif}
  pop r15
  pop r14
  pop r12
  pop rbx
end;
