// This file is part of sha2.pas
// Sha256 i386 asm for optimization when compiler is not smart enough
// Many things learned from gcc compiler
{$ifdef FPC} {$WARN 7105 off, [esp-offset]} {$endif}
procedure SHA256Compress(var Context:TSHA256Context);assembler;
{ [esp] = Pointer to Context
  [esp+4] to [esp+20] are local vars
  [esp+24] to [esp+280] are W array
  We can use eax, ebx, ecx, edx, esi, edi, ebp
}
asm
@start:
  push ebp
  push ebx
  push edi
  push esi
  sub esp, 280
  mov [esp], eax    // Save context

@swap:
  mov edi, [eax+32] // edi = W[0]
  mov ebx, [eax+36]
  mov ecx, [eax+40]
  mov edx, [eax+44]
  mov esi, [eax+48]
  mov ebp, [eax+52]
  bswap edi
  bswap ebx
  bswap ecx
  bswap edx
  bswap esi
  bswap ebp
  mov [esp+24], edi
  mov [esp+28], ebx
  mov [esp+32], ecx
  mov [esp+36], edx
  mov [esp+40], esi
  mov [esp+44], ebp
  mov ebx, [eax+56]
  mov ecx, [eax+60]
  mov edx, [eax+64]
  mov esi, [eax+68]
  mov ebp, [eax+72]
  bswap ebx
  bswap ecx
  bswap edx
  bswap esi
  bswap ebp
  mov [esp+48], ebx
  mov [esp+52], ecx
  mov [esp+56], edx
  mov [esp+60], esi
  mov [esp+64], ebp
  mov ebx, [eax+76]
  mov ecx, [eax+80]
  mov edx, [eax+84]
  mov esi, [eax+88] // esi = W[14]
  mov ebp, [eax+92] // ebp = W[15]
  bswap ebx
  bswap ecx
  bswap edx
  bswap esi
  bswap ebp
  mov [esp+68], ebx
  mov [esp+72], ecx
  mov [esp+76], edx
  mov [esp+80], esi
  mov [esp+84], ebp


{ Pascal code:
  i:=16;
  repeat
    W[i] := LowerSigma1(W[i-2])+W[i-7]+LowerSigma0(W[i-15])+W[i-16];
    W[i+1]:=LowerSigma1(W[i-1])+W[i-6]+LowerSigma0(W[i-14])+W[i-15];
    Inc(i,2);
  until i = 64;
}
@SetW:
  mov ecx, 16
@SetWloop:
  // LowerSigma1(W[i-2])
  mov eax, esi  // esi = W[i-2]
  mov edx, eax
  shr eax, 10
  rol edx, 13
  xor eax, edx
  rol edx, 2
  xor eax, edx
  mov esi, eax
  add esi, [esp+4*ecx-4] // @W[i-7]
  add esi, edi // edi = W[i-16]
  // LowerSigma0(W[i-15])
  mov eax, [esp+4*ecx-36]
  mov ebx, eax // ebx = W[i-15]
  mov edx, eax
  shr eax, 3
  ror edx, 7
  xor eax, edx
  ror edx, 11
  xor eax, edx
  add esi, eax // esi = W[i-2]
  // W[i] := ...
  mov [esp+4*ecx+24], esi
  // LowerSigma1(W[i-1])
  mov eax, ebp  // ebp = W[i-1]
  mov edx, eax
  shr eax, 10
  rol edx, 13
  xor eax, edx
  rol edx, 2
  xor eax, edx
  mov ebp, eax
  add ebp, [esp+4*ecx] // @W[i-6]
  add ebp, ebx // ebx = W[i-15]
  // LowerSigma0(W[i-14])
  mov eax, [esp+4*ecx-32]
  mov edi, eax  // edi = W[i-14], next loop's W[i-16]
  mov edx, eax
  shr eax, 3
  ror edx, 7
  xor eax, edx
  ror edx, 11
  xor eax, edx
  add ebp, eax // ebp = W[i-1]
  // W[i+1] := ...
  mov [esp+4*ecx+28], ebp
  add ecx, 2
  cmp ecx, 64
  jne @SetWloop

{
  A = eax
  B = ebx
  C = ecx
  D = [esp+20]
  E = [esp+4]
  F = [esp+8]
  G = [esp+12]
  H = [esp+16]
}
// We use this for less memory I/O because we skipped first calculation
@PrepareAndSetLocals:
  mov eax, [esp]
  mov ebx, [eax+16] // ebx = E
  mov edi, [eax+20] // edi = F
  mov ebp, [eax+24] // ebp = G
  mov esi, [eax+28] // esi = H
  // T:=H+UpperSigma1(E)+Ch(E,F,G)+K256[i]+W[i];
  add esi, [esp+24] // W[0]
  add esi, dword ptr [K256] // K256[0]
  mov [esp+16], ebp // H:=G
  mov edx, ebp // edx = G
  xor edx, edi // edx = G xor F
  and edx, ebx // edx = (G xor F) and E
  xor edx, ebp // edx = ((G xor F) and E) xor G
  add esi, edx  // esi = H+K256[i]+W[i]+Ch(E,F,G)
  mov [esp+12], edi // G:=F
  mov [esp+8], ebx  // F:=E
  mov ebp, ebx // ebp = E
  ror ebp, 6
  rol ebx, 7
  xor ebx, ebp
  ror ebp, 5
  xor ebp, ebx  // ebp = UpperSigma1(E)
  add esi, ebp  // esi = H+K256[i]+W[i]+Ch(E,F,G)+UpperSigma1(E) = T
  mov edi, [eax+12]
  mov [esp+20], edi // D
  add edi, esi
  mov [esp+4], edi  // E:=D+T
  mov ecx, [eax+8]  // C
  mov ebx, [eax+4]  // B
  mov eax, [eax]    // A


{ Pascal code:
  i:=0;
  repeat
    T:=H+K256[i]+W[i];
    H:=G;
    T:=T+Ch(E,F,G);
    G:=F;
    F:=E;
    T:=T+UpperSigma1(E);
    E:=D+T;
    T:=T+UpperSigma0(A)+Maj(A,B,C);
    D:=C;
    C:=B;
    B:=A;
    A:=T;
    Inc(i);
  until i = 64;
}
@TrueCompress:
  xor edx, edx
  jmp @prepared
@CompressLoop:
  // T:=H+UpperSigma1(E)+Ch(E,F,G)+K256[i]+W[i];
  // T:=H+W[i]+K256[i];
  mov esi, [esp+16] // H
  add esi, [esp+4*edx+24] // W[i]
  add esi, dword ptr [K256+4*edx] // K256[i]
  //  H:=G;
  mov edi, [esp+12]
  mov [esp+16], edi
  // Ch(E,F,G) = ((G xor F) and X) xor G
  xor edi, [esp+8] // edi = G
  and edi, [esp+4]
  xor edi, [esp+12]
  add esi, edi
  //  G:=F;
  mov ebp, [esp+8]
  mov [esp+12], ebp
  //  F:=E;
  mov edi, [esp+4]
  mov [esp+8], edi
  // UpperSigma1(E)
  mov ebp, edi // edi = E
  ror ebp, 6
  rol edi, 7
  xor edi, ebp
  ror ebp, 5
  xor ebp, edi
  add esi, ebp  // T = esi
  //  E:=D+T;
  mov edi, [esp+20]
  add edi, esi
  mov [esp+4], edi

@prepared:
  // T:=T+UpperSigma0(A)+Maj(A,B,C);
  // UpperSigma0(A)
  mov edi, eax
  mov ebp, eax
  ror edi, 2
  rol ebp, 10
  xor edi, ebp
  rol ebp, 9
  xor edi, ebp
  add esi, edi
  // Maj(A,B,C) = ((A or B) and C) or (A and B)
  mov ebp, eax
  mov edi, eax
  or ebp, ebx
  and edi, ebx
  and ebp, ecx
  or edi, ebp
  add esi, edi  // esi = T
  //  D:=C;
  mov [esp+20], ecx
  //  C:=B;
  mov ecx, ebx
  //  B:=A;
  mov ebx, eax
  //  A:=T;
  mov eax, esi
  inc edx
  cmp edx, 64
  jne @CompressLoop

@AddToH:
  mov edi, [esp]
  //Inc(Context.H[0],A);
  add [edi], eax
  //Inc(Context.H[1],B);
  add [edi+4], ebx
  //Inc(Context.H[2],C);
  add [edi+8], ecx
  mov esi, [esp+4]
  mov eax, [esp+8]
  mov ebx, [esp+12]
  mov ecx, [esp+16]
  mov edx, [esp+20]
  //Inc(Context.H[3],D);
  add [edi+12], edx
  //Inc(Context.H[4],E);
  add [edi+16], esi
  //Inc(Context.H[5],F);
  add [edi+20], eax
  //Inc(Context.H[6],G);
  add [edi+24], ebx
  //Inc(Context.H[7],H);
  add [edi+28], ecx

@UpdateMsgLen:
  //Inc(Context.MsgLen,64);
  add dword ptr [edi+104], 64
  adc dword ptr [edi+108], 0

@out:
  add esp, 280
  pop esi
  pop edi
  pop ebx
  pop ebp
end;

