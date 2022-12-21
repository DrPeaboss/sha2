{ SHA2 for fpc/delphi

  Copyright (c) 2022 PeaZomboss

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to
  deal in the Software without restriction, including without limitation the
  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
  sell copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.
}

unit sha2;

// Sha512 is very slow for i386
// Delphi is slower than FPC

{$ifdef fpc}
  {$mode delphi}
  {$AsmMode intel}
  {$ifdef CPUX64}
    {$Optimization USERBP} // It's nice for -O2 or -O3, -O4 will turn it on.
  {$endif}
{$endif}

{$ifndef CPUX86}
  {$define PUREPAS} // Pure pascal, no assembler
{$endif}

{$PointerMath On}

interface

type

{$ifdef DCC}
  PtrInt = NativeInt;
  PtrUInt = NativeUInt;
{$endif}

  TSha2Version = (Sha224,Sha256,Sha384,Sha512,Sha512_224,Sha512_256);
  TSha2Versions = set of TSha2Version;

  TSha224Digest = array[0..27] of Byte;
  TSha256Digest = array[0..31] of Byte;
  TSha384Digest = array[0..47] of Byte;
  TSha512Digest = array[0..63] of Byte;

  PSha2Digest = ^TSha2Digest;

  { TSha2Digest }

  TSha2Digest = record
    class operator Equal(const d1,d2:TSha2Digest):Boolean;
    class operator NotEqual(const d1,d2:TSha2Digest):Boolean;
    class operator Implicit(const d:TSha2Digest):TSha224Digest;
    class operator Implicit(const d:TSha2Digest):TSha256Digest;
    class operator Implicit(const d:TSha2Digest):TSha384Digest;
    class operator Implicit(const d:TSha2Digest):TSha512Digest;
    class operator Implicit(const d:TSha224Digest):TSha2Digest;
    class operator Implicit(const d:TSha256Digest):TSha2Digest;
    class operator Implicit(const d:TSha384Digest):TSha2Digest;
    class operator Implicit(const d:TSha512Digest):TSha2Digest;
    case Integer of
      0:(Datas: array[0..63] of Byte);
      1:(DWrds: array[0..15] of Integer);
      2:(case Integer of
           0:(Digest224: TSha224Digest);
           1:(Digest256: TSha256Digest);
           2:(Digest384: TSha384Digest);
           3:(Digest512: TSha512Digest);
      );
  end;

  TSha256Context = record
    H: array[0..7] of LongWord;
    Buffer: array[0..63] of Byte;
    BufLen: PtrUInt;
    MsgLen: UInt64;
  end;

  TSha512Context = record
    H: array[0..7] of UInt64;
    Buffer: array[0..127] of Byte;
    BufLen: PtrUInt;
    MsgLen: UInt64;
  end;

  TSha2Context = record
    case integer of
      0:(Ctx256: TSha256Context);
      1:(Ctx512: TSha512Context);
  end;


procedure Sha2Init(out Context:TSha2Context;version:TSha2Version);
procedure Sha2Update(var Context:TSha2Context;const buf;len:PtrUInt;version:TSha2Version);
procedure Sha2Final(var Context:TSha2Context;version:TSha2Version;out Digest:TSha2Digest);
function Sha2String(const s:RawByteString;version:TSha2Version):TSha2Digest;
function Sha2Buffer(const buf;len:PtrUInt;version:TSha2Version):TSha2Digest;
function Sha2File(const FileName:RawByteString;version:TSha2Version):TSha2Digest;overload;
function Sha2File(const FileName:UnicodeString;version:TSha2Version):TSha2Digest;overload;
function Sha2Print(const digest:TSha2Digest;version:TSha2Version):String;
function Sha2Match(const d1,d2:TSha2Digest;version:TSha2Version):Boolean;

procedure Sha256Update(var Context:TSha256Context;const buf;len:PtrUInt);
procedure Sha512Update(var Context:TSha512Context;const buf;len:PtrUInt);


implementation

const
  FileBufSize = 1024000; // About 1 MB is nice.

  K256:array[0..63] of LongWord = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2
  );

  K512:array[0..79] of {$ifdef FPC} Int64 {$else} UInt64 {$endif} = (
    $428a2f98d728ae22, $7137449123ef65cd, $b5c0fbcfec4d3b2f, $e9b5dba58189dbbc,
    $3956c25bf348b538, $59f111f1b605d019, $923f82a4af194f9b, $ab1c5ed5da6d8118,
    $d807aa98a3030242, $12835b0145706fbe, $243185be4ee4b28c, $550c7dc3d5ffb4e2,
    $72be5d74f27b896f, $80deb1fe3b1696b1, $9bdc06a725c71235, $c19bf174cf692694,
    $e49b69c19ef14ad2, $efbe4786384f25e3, $0fc19dc68b8cd5b5, $240ca1cc77ac9c65,
    $2de92c6f592b0275, $4a7484aa6ea6e483, $5cb0a9dcbd41fbd4, $76f988da831153b5,
    $983e5152ee66dfab, $a831c66d2db43210, $b00327c898fb213f, $bf597fc7beef0ee4,
    $c6e00bf33da88fc2, $d5a79147930aa725, $06ca6351e003826f, $142929670a0e6e70,
    $27b70a8546d22ffc, $2e1b21385c26c926, $4d2c6dfc5ac42aed, $53380d139d95b3df,
    $650a73548baf63de, $766a0abb3c77b2a8, $81c2c92e47edaee6, $92722c851482353b,
    $a2bfe8a14cf10364, $a81a664bbc423001, $c24b8b70d0f89791, $c76c51a30654be30,
    $d192e819d6ef5218, $d69906245565a910, $f40e35855771202a, $106aa07032bbd1b8,
    $19a4c116b8d2d0c8, $1e376c085141ab53, $2748774cdf8eeb99, $34b0bcb5e19b48a8,
    $391c0cb3c5c95a63, $4ed8aa4ae3418acb, $5b9cca4f7763e373, $682e6ff3d6b2b8a3,
    $748f82ee5defb2fc, $78a5636f43172f60, $84c87814a1f0ab72, $8cc702081a6439ec,
    $90befffa23631e28, $a4506cebde82bde9, $bef9a3f7b2c67915, $c67178f2e372532b,
    $ca273eceea26619c, $d186b8c721c0c207, $eada7dd6cde0eb1e, $f57d4f7fee6ed178,
    $06f067aa72176fba, $0a637dc5a2c898a6, $113f9804bef90dae, $1b710b35131c471b,
    $28db77f523047d84, $32caab7b40c72493, $3c9ebe0a15c9bebc, $431d67c49c100d4c,
    $4cc5d4becb3e42b6, $597f299cfc657e2a, $5fcb6fab3ad6faec, $6c44198c4a475817
  );

  PAD:array[0..127] of Byte = (
    $80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  );


function ROTR(w:LongWord;n:Byte):LongWord;inline;overload;
begin
{$ifdef FPC}
  Result:=RorDWord(w,n);
{$else}
  Result:=w shr n or w shl (32-n);
{$endif}
end;

function ROTR(const qw:UInt64;n:Byte):UInt64;inline;overload;
begin
{$if not defined(FPC) or defined(CPUX86)}
  Result:=qw shr n or qw shl (64-n);
{$else}
  Result:=RorQWord(qw,n);
{$endif}
end;

function ROTL(w:LongWord;n:Byte):LongWord;inline;overload;
begin
{$ifdef FPC}
  Result:=RolDWord(w,n);
{$else}
  Result:=w shl n or w shr (32-n);
{$endif}
end;

function ROTL(const qw:UInt64;n:Byte):UInt64;inline;overload;
begin
{$if not defined(FPC) or defined(CPUX86)}
  Result:=qw shl n or qw shr (64-n);
{$else}
  Result:=RolQWord(qw,n);
{$endif}
end;

(* Thanks to 7-zip project
#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))
*)
function Ch(X,Y,Z:LongWord):LongWord;inline;overload;
begin
  //Result:=(X and Y) xor (not X and Z);
  Result := Z xor (X and (Y xor Z));
end;

function Ch(X,Y,Z:UInt64):UInt64;inline;overload;
begin
  //Result:=(X and Y) xor (not X and Z);
  Result := Z xor (X and (Y xor Z));
end;

function Maj(X,Y,Z:LongWord):LongWord;inline;overload;
begin
  //Result:=(X and Y) xor (X and Z) xor (Y and Z);
  Result := (X and Y) or (Z and (X or Y));
end;

function Maj(X,Y,Z:UInt64):UInt64;inline;overload;
begin
  //Result:=(X and Y) xor (X and Z) xor (Y and Z);
  Result := (X and Y) or (Z and (X or Y));
end;

function UpperSigma0(X:LongWord):LongWord;inline;
begin
  Result:=ROTR(X,2) xor ROTR(X,13) xor ROTR(X,22);
end;

function UpperSigma1(X:LongWord):LongWord;inline;
begin
  Result:=ROTR(X,6) xor ROTR(X,11) xor ROTR(X,25);
end;

function LowerSigma0(X:LongWord):LongWord;inline;
begin
  Result:=ROTR(X,7) xor ROTR(X,18) xor (X shr 3);
end;

function LowerSigma1(X:LongWord):LongWord;inline;
begin
  Result:=ROTR(X,17) xor ROTR(X,19) xor (X shr 10);
end;

function UpperSigma0_512(X:UInt64):UInt64;inline;
begin
  Result:=ROTR(X,28) xor ROTR(X,34) xor ROTR(X,39);
end;

function UpperSigma1_512(X:UInt64):UInt64;inline;
begin
  Result:=ROTR(X,14) xor ROTR(X,18) xor ROTR(X,41);
end;

function LowerSigma0_512(X:UInt64):UInt64;inline;
begin
  Result:=ROTR(X,1) xor ROTR(X,8) xor (X shr 7);
end;

function LowerSigma1_512(X:UInt64):UInt64;inline;
begin
  Result:=ROTR(X,19) xor ROTR(X,61) xor (X shr 6);
end;

{$Ifdef DCC}
function SwapEndian(AValue:Cardinal):Cardinal;inline;overload;
begin
  Result := (AValue shr 24) or (AValue shl 24) or ((AValue shr 8) and $FF00) or ((AValue shl 8) and $FF0000);
end;

function SwapEndian(AValue:UInt64):UInt64;inline;overload;
begin
  Result := UInt64(SwapEndian(Cardinal(AValue))) shl 32 or SwapEndian(Cardinal(AValue shr 32));
end;
{$Endif}

procedure SwapDWords(Src,Dst:PLongWord;Len:PtrInt);inline;
begin
  while Len>=4 do
  begin
    Dst[0]:=SwapEndian(Src[0]);
    Dst[1]:=SwapEndian(Src[1]);
    Dst[2]:=SwapEndian(Src[2]);
    Dst[3]:=SwapEndian(Src[3]);
    Inc(Dst,4);
    Inc(Src,4);
    Dec(Len,4);
  end;
  while Len>0 do
  begin
    Dst^:=SwapEndian(Src^);
    Inc(Dst);
    Inc(Src);
    Dec(Len);
  end;
end;

procedure SwapQWords(Src,Dst:PUInt64;len:PtrInt);inline;
begin
  while Len>=4 do
  begin
    Dst[0]:=SwapEndian(Src[0]);
    Dst[1]:=SwapEndian(Src[1]);
    Dst[2]:=SwapEndian(Src[2]);
    Dst[3]:=SwapEndian(Src[3]);
    Inc(Dst,4);
    Inc(Src,4);
    Dec(Len,4);
  end;
  while len>0 do
  begin
    Dst^:=SwapEndian(Src^);
    Inc(Dst);
    Inc(Src);
    Dec(len);
  end;
end;

procedure Sha2Init(out Context:TSha2Context; version:TSha2Version);
begin
  Context:=Default(TSha2Context);
  case version of
    Sha224: begin
      Context.Ctx256.H[0]:=$c1059ed8;
      Context.Ctx256.H[1]:=$367cd507;
      Context.Ctx256.H[2]:=$3070dd17;
      Context.Ctx256.H[3]:=$f70e5939;
      Context.Ctx256.H[4]:=$ffc00b31;
      Context.Ctx256.H[5]:=$68581511;
      Context.Ctx256.H[6]:=$64f98fa7;
      Context.Ctx256.H[7]:=$befa4fa4;
    end;
    Sha256: begin
      Context.Ctx256.H[0]:=$6a09e667;
      Context.Ctx256.H[1]:=$bb67ae85;
      Context.Ctx256.H[2]:=$3c6ef372;
      Context.Ctx256.H[3]:=$a54ff53a;
      Context.Ctx256.H[4]:=$510e527f;
      Context.Ctx256.H[5]:=$9b05688c;
      Context.Ctx256.H[6]:=$1f83d9ab;
      Context.Ctx256.H[7]:=$5be0cd19;
    end;
    Sha384: begin
      Context.Ctx512.H[0]:=UInt64($cbbb9d5dc1059ed8);
      Context.Ctx512.H[1]:=UInt64($629a292a367cd507);
      Context.Ctx512.H[2]:=UInt64($9159015a3070dd17);
      Context.Ctx512.H[3]:=UInt64($152fecd8f70e5939);
      Context.Ctx512.H[4]:=UInt64($67332667ffc00b31);
      Context.Ctx512.H[5]:=UInt64($8eb44a8768581511);
      Context.Ctx512.H[6]:=UInt64($db0c2e0d64f98fa7);
      Context.Ctx512.H[7]:=UInt64($47b5481dbefa4fa4);
    end;
    Sha512: begin
      Context.Ctx512.H[0]:=UInt64($6a09e667f3bcc908);
      Context.Ctx512.H[1]:=UInt64($bb67ae8584caa73b);
      Context.Ctx512.H[2]:=UInt64($3c6ef372fe94f82b);
      Context.Ctx512.H[3]:=UInt64($a54ff53a5f1d36f1);
      Context.Ctx512.H[4]:=UInt64($510e527fade682d1);
      Context.Ctx512.H[5]:=UInt64($9b05688c2b3e6c1f);
      Context.Ctx512.H[6]:=UInt64($1f83d9abfb41bd6b);
      Context.Ctx512.H[7]:=UInt64($5be0cd19137e2179);
    end;
    Sha512_224: begin
      Context.Ctx512.H[0]:=UInt64($8c3d37c819544da2);
      Context.Ctx512.H[1]:=UInt64($73e1996689dcd4d6);
      Context.Ctx512.H[2]:=UInt64($1dfab7ae32ff9c82);
      Context.Ctx512.H[3]:=UInt64($679dd514582f9fcf);
      Context.Ctx512.H[4]:=UInt64($0f6d2b697bd44da8);
      Context.Ctx512.H[5]:=UInt64($77e36f7304c48942);
      Context.Ctx512.H[6]:=UInt64($3f9d85a86a1d36c8);
      Context.Ctx512.H[7]:=UInt64($1112e6ad91d692a1);
    end;
    Sha512_256: begin
      Context.Ctx512.H[0]:=UInt64($22312194fc2bf72c);
      Context.Ctx512.H[1]:=UInt64($9f555fa3c84c64c2);
      Context.Ctx512.H[2]:=UInt64($2393b86b6f53b151);
      Context.Ctx512.H[3]:=UInt64($963877195940eabd);
      Context.Ctx512.H[4]:=UInt64($96283ee2a88effe3);
      Context.Ctx512.H[5]:=UInt64($be5e1e2553863992);
      Context.Ctx512.H[6]:=UInt64($2b0199fc2c85b8aa);
      Context.Ctx512.H[7]:=UInt64($0eb72ddc81c52ca2);
    end;
  end;
end;

procedure Sha2Update(var Context:TSha2Context; const buf; len:PtrUInt; version:TSha2Version);
begin
  if version in [Sha224,Sha256] then
    Sha256Update(Context.Ctx256,buf,len)
  else
    Sha512Update(Context.Ctx512,buf,len);
end;

procedure Sha2Final(var Context:TSha2Context; version:TSha2Version; out Digest:TSha2Digest);
var
  MsgLen:UInt64;
  Pads:LongInt;
begin
  Digest:=Default(TSha2Digest);
  case version of
    Sha224, Sha256:
      begin
        MsgLen:=(Context.Ctx256.MsgLen+Context.Ctx256.BufLen)*8;
        MsgLen:=SwapEndian(MsgLen);
        if Context.Ctx256.BufLen>56 then
          Pads:=120-Context.Ctx256.BufLen
        else
          Pads:=56-Context.Ctx256.BufLen;
        Sha256Update(Context.Ctx256,PAD,Pads);
        Sha256Update(Context.Ctx256,MsgLen,8);
        SwapDWords(@Context.Ctx256.H,@Digest,8);
      end;
    Sha384, Sha512, Sha512_224, Sha512_256:
      begin
        MsgLen:=(Context.Ctx512.MsgLen+Context.Ctx512.BufLen)*8;
        MsgLen:=SwapEndian(MsgLen);
        if Context.Ctx512.BufLen>112 then
          Pads:=240-Context.Ctx512.BufLen
        else
          Pads:=112-Context.Ctx512.BufLen;
        Sha512Update(Context.Ctx512,PAD,Pads);
        FillChar(Context.Ctx512.Buffer[Context.Ctx512.BufLen],8,0);
        Inc(Context.Ctx512.BufLen,8);
        Sha512Update(Context.Ctx512,MsgLen,8);
        SwapQWords(@Context.Ctx512.H,@Digest,8);
      end;
  end;
  Context:=Default(TSha2Context);
end;

function Sha2String(const s:RawByteString; version:TSha2Version):TSha2Digest;
begin
  Result:=Sha2Buffer(s[1],length(s),version);
end;

function Sha2Buffer(const buf; len:PtrUInt; version:TSha2Version):TSha2Digest;
var
  ctx:TSha2Context;
begin
  Sha2Init(ctx,version);
  case version of
    Sha224, Sha256:
      Sha256Update(ctx.Ctx256,buf,len);
    Sha384, Sha512, Sha512_224, Sha512_256:
      Sha512Update(ctx.Ctx512,buf,len);
  end;
  Sha2Final(ctx,version,Result);
end;

function Sha2File(const FileName:RawByteString; version:TSha2Version):TSha2Digest;
type
  TSha2UpdateProc = procedure(var ctx;const buf;len:Integer);
var
  F:File;
  fm:Byte;
  buf:Pointer;
  ReadCount:Integer;
  Context:TSha2Context;
  Sha2Update:TSha2UpdateProc;
begin
  Result:=Default(TSha2Digest);
  ReadCount:=0;
  case version of
    Sha224, Sha256:
      Sha2Update:=@Sha256Update;
    Sha384, Sha512, Sha512_224, Sha512_256:
      Sha2Update:=@Sha512Update;
  end;
  Assign(F,FileName);
  Reset(F,1);
  fm:=FileMode;
  FileMode:=0;
  if IOResult=0 then
  begin
    GetMem(buf,FileBufSize);
    Sha2Init(Context,version);
    repeat
      BlockRead(F,buf^,FileBufSize,ReadCount);
      if ReadCount>0 then
        Sha2Update(Context,buf^,ReadCount);
    until ReadCount<FileBufSize;
    Sha2Final(Context,version,Result);
    Freemem(buf);
    Close(F);
  end;
  FileMode:=fm;
end;

function Sha2File(const FileName:UnicodeString; version:TSha2Version):TSha2Digest;
type
  TSha2UpdateProc = procedure(ctx:Pointer;const buf;len:Integer);
var
  F:File;
  fm:Byte;
  buf:Pointer;
  ReadCount:Integer;
  Context:TSha2Context;
  Sha2Update:TSha2UpdateProc;
begin
  Result:=Default(TSha2Digest);
  ReadCount:=0;
  case version of
    Sha224, Sha256:
      Sha2Update:=@Sha256Update;
    Sha384, Sha512, Sha512_224, Sha512_256:
      Sha2Update:=@Sha512Update;
  end;
  Assign(F,FileName);
  Reset(F,1);
  fm:=FileMode;
  FileMode:=0;
  if IOResult=0 then
  begin
    GetMem(buf,FileBufSize);
    Sha2Init(Context,version);
    repeat
      BlockRead(F,buf^,FileBufSize,ReadCount);
      if ReadCount>0 then
        Sha2Update(@Context,buf^,ReadCount);
    until ReadCount<FileBufSize;
    Sha2Final(Context,version,Result);
    Freemem(buf);
    Close(F);
  end;
  FileMode:=fm;
end;

function Sha2Print(const digest:TSha2Digest; version:TSha2Version):String;
const
  HexTable:array[0..15] of Char='0123456789abcdef';
  DigestLen:array[Sha224..Sha512_256] of Integer = (28, 32, 48, 64, 28, 32);
var
  i,Len:Integer;
  p:PChar;
begin
  Result:='';
  Len:=DigestLen[version];
  SetLength(Result,Len*2);
  p:=PChar(Result);
  for i:=0 to Len-1 do
  begin
    p[0]:=HexTable[digest.Datas[i] shr 4 and 15];
    p[1]:=HexTable[digest.Datas[i] and 15];
    inc(p,2);
  end;
end;

function Sha2Match(const d1,d2:TSha2Digest; version:TSha2Version):Boolean;
const
  DigestLen:array[Sha224..Sha512_256] of Integer = (28, 32, 48, 64, 28, 32);
var
  Len,i:Integer;
begin
  Result:=False;
  Len:=DigestLen[version];
  for i:=0 to Len-1 do
    if d1.Datas[i]<>d2.Datas[i] then
      Exit;
  Result:=True;
end;


{$if not Defined(PUREPAS) and Defined(CPUX86)}
{$I sha256i386.inc}
{$else}
procedure Sha256Compress(var Context:TSha256Context);
var
  A,B,C,D,E,F,G,H,T1,T2:LongWord;
  W:array[0..63] of LongWord;
  i:Integer;
begin
  SwapDWords(@Context.Buffer,@W[0],16);
  for i:=16 to 63 do
    W[i]:=LowerSigma1(W[i-2])+W[i-7]+LowerSigma0(W[i-15])+W[i-16];
  A:=Context.H[0];
  B:=Context.H[1];
  C:=Context.H[2];
  D:=Context.H[3];
  E:=Context.H[4];
  F:=Context.H[5];
  G:=Context.H[6];
  H:=Context.H[7];
  for i:=0 to 63 do
  begin
    T1:=H+UpperSigma1(E)+Ch(E,F,G)+K256[i]+W[i];
    T2:=UpperSigma0(A)+Maj(A,B,C);
    H:=G;
    G:=F;
    F:=E;
    E:=D+T1;
    D:=C;
    C:=B;
    B:=A;
    A:=T1+T2;
  end;
  Inc(Context.H[0],A);
  Inc(Context.H[1],B);
  Inc(Context.H[2],C);
  Inc(Context.H[3],D);
  Inc(Context.H[4],E);
  Inc(Context.H[5],F);
  Inc(Context.H[6],G);
  Inc(Context.H[7],H);
  Inc(Context.MsgLen,64);
end;
{$endif}

procedure Sha256Update(var Context:TSha256Context; const buf; len:PtrUInt);
var
  p:PByte;
  N:PtrUInt;
begin
  p:=@buf;
  if Context.BufLen>0 then
  begin
    N:=64-Context.BufLen;
    if len<N then
      N:=len;
    move(p^,Context.Buffer[Context.BufLen],N);
    Inc(Context.BufLen,N);
    Inc(p,N);
    Dec(len,N);
    if Context.BufLen=64 then
    begin
      Sha256Compress(Context);
      Context.BufLen:=0;
    end;
  end;
  while len>=64 do
  begin
    move(p^,Context.Buffer,64);
    Sha256Compress(Context);
    Inc(p,64);
    Dec(len,64);
  end;
  if len>0 then
  begin
    move(p^,Context.Buffer,len);
    Context.BufLen:=len;
  end;
end;

procedure Sha512Compress(var Context:TSha512Context);
var
  A,B,C,D,E,F,G,H,T1,T2: UInt64;
  W: array[0..79] of UInt64;
  i: Integer;
begin
  SwapQWords(@Context.Buffer,@W,16);
  for i:=16 to 79 do
    W[i]:=LowerSigma1_512(W[i-2])+W[i-7]+LowerSigma0_512(W[i-15])+W[i-16];
  A:=Context.H[0];
  B:=Context.H[1];
  C:=Context.H[2];
  D:=Context.H[3];
  E:=Context.H[4];
  F:=Context.H[5];
  G:=Context.H[6];
  H:=Context.H[7];
  for i:=0 to 79 do
  begin
    T1:=H+UpperSigma1_512(E)+Ch(E,F,G)+K512[i]+W[i];
    T2:=UpperSigma0_512(A)+Maj(A,B,C);
    H:=G;
    G:=F;
    F:=E;
    E:=D+T1;
    D:=C;
    C:=B;
    B:=A;
    A:=T1+T2;
  end;
  Inc(Context.H[0],A);
  Inc(Context.H[1],B);
  Inc(Context.H[2],C);
  Inc(Context.H[3],D);
  Inc(Context.H[4],E);
  Inc(Context.H[5],F);
  Inc(Context.H[6],G);
  Inc(Context.H[7],H);
  Inc(Context.MsgLen,128);
end;

procedure Sha512Update(var Context:TSha512Context; const buf; len:PtrUInt);
var
  p:PByte;
  N:PtrUInt;
begin
  p:=@buf;
  if Context.BufLen>0 then
  begin
    N:=128-Context.BufLen;
    if len<N then
      N:=len;
    move(p^,Context.Buffer[Context.BufLen],N);
    Inc(Context.BufLen,N);
    Inc(p,N);
    Dec(len,N);
    if Context.BufLen=128 then
    begin
      Sha512Compress(Context);
      Context.BufLen:=0;
    end;
  end;
  while len>=128 do
  begin
    move(p^,Context.Buffer,128);
    Sha512Compress(Context);
    Inc(p,128);
    Dec(len,128);
  end;
  if len>0 then
  begin
    move(p^,Context.Buffer,len);
    Context.BufLen:=len;
  end;
end;

{ TSha2Digest }

class operator TSha2Digest.Equal(const d1,d2:TSha2Digest):Boolean;
var
  i:Integer;
begin
  Result:=False;
  for i:=0 to 15 do
    if d1.DWrds[i]<>d2.DWrds[i] then
      Exit;
  Result:=True;
end;

class operator TSha2Digest.NotEqual(const d1,d2:TSha2Digest):Boolean;
var
  i:Integer;
begin
  Result:=False;
  for i:=0 to 15 do
    if d1.DWrds[i]=d2.DWrds[i] then
      Exit;
  Result:=True;
end;

class operator TSha2Digest.Implicit(const d:TSha2Digest):TSha224Digest;
begin
  Result:=d.Digest224;
end;

class operator TSha2Digest.Implicit(const d:TSha2Digest):TSha256Digest;
begin
  Result:=d.Digest256;
end;

class operator TSha2Digest.Implicit(const d:TSha2Digest):TSha384Digest;
begin
  Result:=d.Digest384;
end;

class operator TSha2Digest.Implicit(const d:TSha2Digest):TSha512Digest;
begin
  Result:=d.Digest512;
end;

class operator TSha2Digest.Implicit(const d:TSha224Digest):TSha2Digest;
begin
  Result.Digest224:=d;
end;

class operator TSha2Digest.Implicit(const d:TSha256Digest):TSha2Digest;
begin
  Result.Digest256:=d;
end;

class operator TSha2Digest.Implicit(const d:TSha384Digest):TSha2Digest;
begin
  Result.Digest384:=d;
end;

class operator TSha2Digest.Implicit(const d:TSha512Digest):TSha2Digest;
begin
  Result.Digest512:=d;
end;

end.
