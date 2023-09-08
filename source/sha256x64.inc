// This file is part of sha2.pas
// Sha256 x86_64 asm for optimization
procedure SHA256Compress(var Context:TSHA256Context);assembler;
const
  PK256:Pointer = @K256;
var
  W:Array[0..63] of Cardinal;
asm
  push rbx
  push r12
  push r14
  push r15
{$ifdef MSWINDOWS}
  push rdi
  push rsi
  mov r15, rcx  // save the context
{$else}
  mov r15, rdi  // save the context
{$endif}
  mov r14, [rip+PK256]
  // swap
  mov edi, [r15+32]  // W[0]
  bswap edi
  mov dword ptr W[0], edi
  mov eax, [r15+36]
  bswap eax
  mov dword ptr W[4], eax
  mov eax, [r15+40]
  bswap eax
  mov dword ptr W[8], eax
  mov eax, [r15+44]
  bswap eax
  mov dword ptr W[12], eax
  mov eax, [r15+48]
  bswap eax
  mov dword ptr W[16], eax
  mov eax, [r15+52]
  bswap eax
  mov dword ptr W[20], eax
  mov eax, [r15+56]
  bswap eax
  mov dword ptr W[24], eax
  mov eax, [r15+60]
  bswap eax
  mov dword ptr W[28], eax
  mov eax, [r15+64]
  bswap eax
  mov dword ptr W[32], eax
  mov eax, [r15+68]
  bswap eax
  mov dword ptr W[36], eax
  mov eax, [r15+72]
  bswap eax
  mov dword ptr W[40], eax
  mov eax, [r15+76]
  bswap eax
  mov dword ptr W[44], eax
  mov eax, [r15+80]
  bswap eax
  mov dword ptr W[48], eax
  mov eax, [r15+84]
  bswap eax
  mov dword ptr W[52], eax
  mov esi, [r15+88] // W[14]
  bswap esi
  mov dword ptr W[56], esi
  mov r8d, [r15+92] // W[15]
  bswap r8d
  mov dword ptr W[60], r8d

  //i:=16;
  //repeat
  //  W[i] := LowerSigma1(W[i-2])+W[i-7]+LowerSigma0(W[i-15])+W[i-16];
  //  W[i+1]:=LowerSigma1(W[i-1])+W[i-6]+LowerSigma0(W[i-14])+W[i-15];
  //  Inc(i,2);
  //until i = 64;
  mov rcx, 16
@L1:
  // LowerSigma1(W[i-2])
  mov eax, esi  // esi = W[i-2]
  mov edx, eax
  shr eax, 10
  rol edx, 13
  xor eax, edx
  rol edx, 2
  xor eax, edx
  mov esi, eax
  add esi, dword ptr W[rcx*4-28] // @W[i-7]
  add esi, edi // edi = W[i-16]
  // LowerSigma0(W[i-15])
  mov eax, dword ptr W[rcx*4-60]
  mov ebx, eax // ebx = W[i-15]
  mov edx, eax
  shr eax, 3
  ror edx, 7
  xor eax, edx
  ror edx, 11
  xor eax, edx
  add esi, eax // esi = W[i-2]
  // W[i] := ...
  mov dword ptr W[rcx*4], esi
  // LowerSigma1(W[i-1])
  mov eax, r8d  // r8d = W[i-1]
  mov edx, eax
  shr eax, 10
  rol edx, 13
  xor eax, edx
  rol edx, 2
  xor eax, edx
  mov r8d, eax
  add r8d, dword ptr W[rcx*4-24] // @W[i-6]
  add r8d, ebx // ebx = W[i-15]
  // LowerSigma0(W[i-14])
  mov eax, dword ptr W[rcx*4-56]
  mov edi, eax  // edi = W[i-14], next loop's W[i-16]
  mov edx, eax
  shr eax, 3
  ror edx, 7
  xor eax, edx
  ror edx, 11
  xor eax, edx
  add r8d, eax // r8d = W[i-1]
  // W[i+1] := ...
  mov dword ptr W[rcx*4+4], r8d
  add rcx, 2
  cmp rcx, 64
  jne @L1

  //A:=Context.H[0];
  //B:=Context.H[1];
  //C:=Context.H[2];
  //D:=Context.H[3];
  //E:=Context.H[4];
  //F:=Context.H[5];
  //G:=Context.H[6];
  //H:=Context.H[7];
  mov eax, [r15]    // A
  mov ebx, [r15+4]  // B
  mov ecx, [r15+8]  // C
  mov edx, [r15+12] // D
  mov edi, [r15+16] // E
  mov esi, [r15+20] // F
  mov r8d, [r15+24] // G
  mov r9d, [r15+28] // H

  //i:=0;
  //repeat
  //  T:=H+K256[i]+W[i];
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
  //until i = 64;
  xor r10, r10
@L2:
  // T:=W[i]+K256[i]+H
  mov r11d, dword ptr W[r10*4]
  add r11d, dword ptr [r14+r10*4]
  add r11d, r9d
  // H:=G
  mov r9d, r8d
  // T:=T+Ch(E,F,G) // Ch = G xor (E and (F xor G))
  xor r8d, esi   // xor F
  and r8d, edi   // and E
  xor r8d, r9d   // xor G
  add r11d, r8d
  // G:=F
  mov r8d, esi
  // F:=E
  mov esi, edi
  // T:=T+UpperSigma1(E) = ROTR(X,6) xor ROTR(X,11) xor ROTR(X,25)
  mov r12d, edi
  ror edi, 6
  ror r12d, 11
  xor edi, r12d
  ror r12d, 14
  xor edi, r12d
  add r11d, edi
  // E:=D+T
  mov edi, edx
  add edi, r11d
  // T:=T+UpperSigma0(A)+Maj(A,B,C)
  // UpperSigma0(A) = ROTR(X,2) xor ROTR(X,13) xor ROTR(X,22)
  mov edx, eax
  mov r12d, eax
  ror edx, 2
  ror r12d, 13
  xor edx, r12d
  ror r12d, 9
  xor edx, r12d
  add r11d, edx
  // Maj(A,B,C) = (A and B) or (C and (A or B))
  mov edx, eax
  mov r12d, eax
  or edx, ebx
  and edx, ecx
  and r12d, ebx
  or edx, r12d
  add r11d, edx
  // D:=C
  mov edx, ecx
  // C:=B
  mov  ecx, ebx
  // B:=A
  mov ebx, eax
  // A:=T
  mov eax, r11d
  // Loop
  inc r10
  cmp r10, 64
  jl @L2

  //Inc(Context.H[0],A);
  //Inc(Context.H[1],B);
  //Inc(Context.H[2],C);
  //Inc(Context.H[3],D);
  //Inc(Context.H[4],E);
  //Inc(Context.H[5],F);
  //Inc(Context.H[6],G);
  //Inc(Context.H[7],H);
  add [r15], eax
  add [r15+4], ebx
  add [r15+8], ecx
  add [r15+12], edx
  add [r15+16], edi
  add [r15+20], esi
  add [r15+24], r8d
  add [r15+28], r9d

{$ifdef MSWINDOWS}
  pop rsi
  pop rdi
{$endif}
  pop r15
  pop r14
  pop r12
  pop rbx
end;

