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

{$define PUREPAS} // Pure pascal, no assembler
{$ifdef CPUX86}
  {$UnDef PUREPAS}
{$endif}
{$ifdef CPUX64}
  {$UnDef PUREPAS}
{$endif}

{$PointerMath On}

interface

type

{$ifdef DCC}
  PtrInt = NativeInt;
  PtrUInt = NativeUInt;
{$endif}

  TSHA2Version  = (SHA224,SHA256,SHA384,SHA512,SHA512_224,SHA512_256);
  TSHA2Versions = set of TSHA2Version;

  TSHA224Digest = array[0..27] of Byte;
  TSHA256Digest = array[0..31] of Byte;
  TSHA384Digest = array[0..47] of Byte;
  TSHA512Digest = array[0..63] of Byte;

  PSHA2Digest = ^TSHA2Digest;

  { TSHA2Digest }

  TSHA2Digest = record
  public
    function ToString(LowerCase:Boolean=True):String;
    class operator Equal(const d1,d2:TSHA2Digest):Boolean;
    class operator NotEqual(const d1,d2:TSHA2Digest):Boolean;
    class operator Implicit(const d:TSHA2Digest):TSHA224Digest;
    class operator Implicit(const d:TSHA2Digest):TSHA256Digest;
    class operator Implicit(const d:TSHA2Digest):TSHA384Digest;
    class operator Implicit(const d:TSHA2Digest):TSHA512Digest;
    class operator Implicit(const d:TSHA224Digest):TSHA2Digest;
    class operator Implicit(const d:TSHA256Digest):TSHA2Digest;
    class operator Implicit(const d:TSHA384Digest):TSHA2Digest;
    class operator Implicit(const d:TSHA512Digest):TSHA2Digest;
  public
    Version:TSHA2Version;
    case Integer of
      0:(Datas: array[0..63] of Byte);
      1:(DWrds: array[0..15] of Integer);
      2:(case Integer of
           0:(Digest224: TSHA224Digest);
           1:(Digest256: TSHA256Digest);
           2:(Digest384: TSHA384Digest);
           3:(Digest512: TSHA512Digest);
      );
  end;

  TSHA256Context = record
    H: array[0..7] of LongWord;
    Buffer: array[0..63] of Byte;
    BufLen: PtrUInt;
    MsgLen: UInt64;
  end;

  TSHA512Context = record
    H: array[0..7] of UInt64;
    Buffer: array[0..127] of Byte;
    BufLen: PtrUInt;
    MsgLen: UInt64;
  end;

  TSHA2Context = record
    Version:TSHA2Version;
    case integer of
      0:(Ctx256: TSHA256Context);
      1:(Ctx512: TSHA512Context);
  end;

  TSHA2 = record
  private
    Ctx:TSHA2Context;
  public
    procedure Init(Version:TSHA2Version);
    procedure Update(const Buf;Len:PtrUInt);overload;
    procedure Update(P:Pointer;Len:PtrUInt);overload;
    procedure Final(out Digest:TSHA2Digest);overload;
    function  Final:TSHA2Digest;overload;
    class function HashBuffer(const Buf;Len:PtrUInt;Version:TSHA2Version):TSHA2Digest;overload;static;
    class function HashString(const S:RawByteString;Version:TSHA2Version):TSHA2Digest;overload;static;
  end;


procedure SHA2Init(out Context:TSHA2Context;version:TSHA2Version);
procedure SHA2Update(var Context:TSHA2Context;const buf;len:PtrUInt);
procedure SHA2Final(var Context:TSHA2Context;out Digest:TSHA2Digest);
function SHA2String(const s:RawByteString;version:TSHA2Version):TSHA2Digest;
function SHA2Buffer(const buf;len:PtrUInt;version:TSHA2Version):TSHA2Digest;
function SHA2File(const FileName:RawByteString;version:TSHA2Version):TSHA2Digest;overload;
function SHA2File(const FileName:UnicodeString;version:TSHA2Version):TSHA2Digest;overload;
function SHA2Print(const digest:TSHA2Digest;LowerCase:Boolean=True):String;
function SHA2Match(const d1,d2:TSHA2Digest):Boolean;

procedure SHA256Update(var Context:TSHA256Context;const buf;len:PtrUInt);
procedure SHA512Update(var Context:TSHA512Context;const buf;len:PtrUInt);


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

procedure SHA2Init(out Context:TSHA2Context; version:TSHA2Version);
begin
  Context:=Default(TSHA2Context);
  Context.Version:=Version;
  case version of
    SHA224: begin
      Context.Ctx256.H[0]:=$c1059ed8;
      Context.Ctx256.H[1]:=$367cd507;
      Context.Ctx256.H[2]:=$3070dd17;
      Context.Ctx256.H[3]:=$f70e5939;
      Context.Ctx256.H[4]:=$ffc00b31;
      Context.Ctx256.H[5]:=$68581511;
      Context.Ctx256.H[6]:=$64f98fa7;
      Context.Ctx256.H[7]:=$befa4fa4;
    end;
    SHA256: begin
      Context.Ctx256.H[0]:=$6a09e667;
      Context.Ctx256.H[1]:=$bb67ae85;
      Context.Ctx256.H[2]:=$3c6ef372;
      Context.Ctx256.H[3]:=$a54ff53a;
      Context.Ctx256.H[4]:=$510e527f;
      Context.Ctx256.H[5]:=$9b05688c;
      Context.Ctx256.H[6]:=$1f83d9ab;
      Context.Ctx256.H[7]:=$5be0cd19;
    end;
    SHA384: begin
      Context.Ctx512.H[0]:=UInt64($cbbb9d5dc1059ed8);
      Context.Ctx512.H[1]:=UInt64($629a292a367cd507);
      Context.Ctx512.H[2]:=UInt64($9159015a3070dd17);
      Context.Ctx512.H[3]:=UInt64($152fecd8f70e5939);
      Context.Ctx512.H[4]:=UInt64($67332667ffc00b31);
      Context.Ctx512.H[5]:=UInt64($8eb44a8768581511);
      Context.Ctx512.H[6]:=UInt64($db0c2e0d64f98fa7);
      Context.Ctx512.H[7]:=UInt64($47b5481dbefa4fa4);
    end;
    SHA512: begin
      Context.Ctx512.H[0]:=UInt64($6a09e667f3bcc908);
      Context.Ctx512.H[1]:=UInt64($bb67ae8584caa73b);
      Context.Ctx512.H[2]:=UInt64($3c6ef372fe94f82b);
      Context.Ctx512.H[3]:=UInt64($a54ff53a5f1d36f1);
      Context.Ctx512.H[4]:=UInt64($510e527fade682d1);
      Context.Ctx512.H[5]:=UInt64($9b05688c2b3e6c1f);
      Context.Ctx512.H[6]:=UInt64($1f83d9abfb41bd6b);
      Context.Ctx512.H[7]:=UInt64($5be0cd19137e2179);
    end;
    SHA512_224: begin
      Context.Ctx512.H[0]:=UInt64($8c3d37c819544da2);
      Context.Ctx512.H[1]:=UInt64($73e1996689dcd4d6);
      Context.Ctx512.H[2]:=UInt64($1dfab7ae32ff9c82);
      Context.Ctx512.H[3]:=UInt64($679dd514582f9fcf);
      Context.Ctx512.H[4]:=UInt64($0f6d2b697bd44da8);
      Context.Ctx512.H[5]:=UInt64($77e36f7304c48942);
      Context.Ctx512.H[6]:=UInt64($3f9d85a86a1d36c8);
      Context.Ctx512.H[7]:=UInt64($1112e6ad91d692a1);
    end;
    SHA512_256: begin
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

procedure SHA2Update(var Context:TSHA2Context; const buf; len:PtrUInt);
begin
  if Context.Version in [SHA224,SHA256] then
    SHA256Update(Context.Ctx256,buf,len)
  else
    SHA512Update(Context.Ctx512,buf,len);
end;

procedure SHA2Final(var Context:TSHA2Context; out Digest:TSHA2Digest);
var
  MsgLen:UInt64;
  Pads:LongInt;
begin
  Digest:=Default(TSHA2Digest);
  Digest.Version:=Context.Version;
  case Context.Version of
    SHA224, SHA256:
      begin
        MsgLen:=(Context.Ctx256.MsgLen+Context.Ctx256.BufLen)*8;
        MsgLen:=SwapEndian(MsgLen);
        if Context.Ctx256.BufLen>56 then
          Pads:=120-Context.Ctx256.BufLen
        else
          Pads:=56-Context.Ctx256.BufLen;
        SHA256Update(Context.Ctx256,PAD,Pads);
        SHA256Update(Context.Ctx256,MsgLen,8);
        SwapDWords(@Context.Ctx256.H,@Digest.Datas,8);
      end;
    SHA384, SHA512, SHA512_224, SHA512_256:
      begin
        MsgLen:=(Context.Ctx512.MsgLen+Context.Ctx512.BufLen)*8;
        MsgLen:=SwapEndian(MsgLen);
        if Context.Ctx512.BufLen>112 then
          Pads:=240-Context.Ctx512.BufLen
        else
          Pads:=112-Context.Ctx512.BufLen;
        SHA512Update(Context.Ctx512,PAD,Pads);
        FillChar(Context.Ctx512.Buffer[Context.Ctx512.BufLen],8,0);
        Inc(Context.Ctx512.BufLen,8);
        SHA512Update(Context.Ctx512,MsgLen,8);
        SwapQWords(@Context.Ctx512.H,@Digest.Datas,8);
      end;
  end;
  Context:=Default(TSHA2Context);
end;

function SHA2String(const s:RawByteString; version:TSHA2Version):TSHA2Digest;
begin
  Result:=SHA2Buffer(s[1],length(s),version);
end;

function SHA2Buffer(const buf; len:PtrUInt; version:TSHA2Version):TSHA2Digest;
var
  ctx:TSHA2Context;
begin
  SHA2Init(ctx,version);
  case version of
    SHA224, SHA256:
      SHA256Update(ctx.Ctx256,buf,len);
    SHA384, SHA512, SHA512_224, SHA512_256:
      SHA512Update(ctx.Ctx512,buf,len);
  end;
  SHA2Final(ctx,Result);
end;

function SHA2File(const FileName:RawByteString; version:TSHA2Version):TSHA2Digest;
type
  TSHA2UpdateProc = procedure(var ctx;const buf;len:Integer);
var
  F:File;
  fm:Byte;
  buf:Pointer;
  ReadCount:Integer;
  Context:TSHA2Context;
  SHA2Update:TSHA2UpdateProc;
begin
  Result:=Default(TSHA2Digest);
  ReadCount:=0;
  SHA2Update:=@SHA256Update;
  if version in [SHA384, SHA512, SHA512_224, SHA512_256] then
    SHA2Update:=@SHA512Update;
  Assign(F,FileName);
  Reset(F,1);
  fm:=FileMode;
  FileMode:=0;
  if IOResult=0 then
  begin
    GetMem(buf,FileBufSize);
    SHA2Init(Context,version);
    repeat
      BlockRead(F,buf^,FileBufSize,ReadCount);
      if ReadCount>0 then
        SHA2Update(Context,buf^,ReadCount);
    until ReadCount<FileBufSize;
    SHA2Final(Context,Result);
    Freemem(buf);
    Close(F);
  end;
  FileMode:=fm;
end;

function SHA2File(const FileName:UnicodeString; version:TSHA2Version):TSHA2Digest;
type
  TSHA2UpdateProc = procedure(ctx:Pointer;const buf;len:Integer);
var
  F:File;
  fm:Byte;
  buf:Pointer;
  ReadCount:Integer;
  Context:TSHA2Context;
  SHA2Update:TSHA2UpdateProc;
begin
  Result:=Default(TSHA2Digest);
  ReadCount:=0;
  SHA2Update:=@SHA256Update;
  if version in [SHA384, SHA512, SHA512_224, SHA512_256] then
    SHA2Update:=@SHA512Update;
  Assign(F,FileName);
  Reset(F,1);
  fm:=FileMode;
  FileMode:=0;
  if IOResult=0 then
  begin
    GetMem(buf,FileBufSize);
    SHA2Init(Context,version);
    repeat
      BlockRead(F,buf^,FileBufSize,ReadCount);
      if ReadCount>0 then
        SHA2Update(@Context,buf^,ReadCount);
    until ReadCount<FileBufSize;
    SHA2Final(Context,Result);
    Freemem(buf);
    Close(F);
  end;
  FileMode:=fm;
end;

function SHA2Print(const digest:TSHA2Digest; LowerCase:Boolean):String;
const
  HexTableLower:array[0..15] of Char='0123456789abcdef';
  HexTableUpper:array[0..15] of Char='0123456789ABCDEF';
  SHA2DigestLen:array[SHA224..SHA512_256] of Byte = (28, 32, 48, 64, 28, 32);
var
  i,Len:Integer;
  p,ptbl:PChar;
begin
  Result:='';
  if LowerCase then
    ptbl:=@HexTableLower
  else
    ptbl:=@HexTableUpper;
  Len:=SHA2DigestLen[digest.Version];
  SetLength(Result,Len*2);
  p:=PChar(Result);
  for i:=0 to Len-1 do
  begin
    p[0]:=ptbl[digest.Datas[i] shr 4 and 15];
    p[1]:=ptbl[digest.Datas[i] and 15];
    inc(p,2);
  end;
end;

function SHA2Match(const d1,d2:TSHA2Digest):Boolean;
const
  SHA2DigestDWords:Array[SHA224..SHA512_256] of Byte = (7, 8, 12, 16, 7, 8);
var
  i:Integer;
begin
  Result:=False;
  if d1.Version<>d2.Version then
    Exit;
  for i:=0 to SHA2DigestDWords[d1.Version]-1 do
    if d1.DWrds[i]<>d2.DWrds[i] then
      Exit;
  Result:=True;
end;

{$ifdef PUREPAS}
procedure SHA256Compress(var Context:TSHA256Context);
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
{$else not PUREPAS}
{$ifdef CPUX86}
{$I sha256i386.inc}
{$endif}
{$ifdef CPUX64}
{$I sha256x64.inc}
{$endif}
{$endif PUREPAS}

procedure SHA256Update(var Context:TSHA256Context; const buf; len:PtrUInt);
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
      SHA256Compress(Context);
      Context.BufLen:=0;
    end;
  end;
  while len>=64 do
  begin
    move(p^,Context.Buffer,64);
    SHA256Compress(Context);
    Inc(p,64);
    Dec(len,64);
  end;
  if len>0 then
  begin
    move(p^,Context.Buffer,len);
    Context.BufLen:=len;
  end;
end;

procedure SHA512Compress(var Context:TSHA512Context);
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

procedure SHA512Update(var Context:TSHA512Context; const buf; len:PtrUInt);
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
      SHA512Compress(Context);
      Context.BufLen:=0;
    end;
  end;
  while len>=128 do
  begin
    move(p^,Context.Buffer,128);
    SHA512Compress(Context);
    Inc(p,128);
    Dec(len,128);
  end;
  if len>0 then
  begin
    move(p^,Context.Buffer,len);
    Context.BufLen:=len;
  end;
end;

{ TSHA2Digest }

function TSHA2Digest.ToString(LowerCase:Boolean):String;
begin
  Result:=SHA2Print(Self,LowerCase);
end;

class operator TSHA2Digest.Equal(const d1,d2:TSHA2Digest):Boolean;
begin
  Result:=SHA2Match(d1,d2);
end;

class operator TSHA2Digest.NotEqual(const d1,d2:TSHA2Digest):Boolean;
begin
  Result:=not SHA2Match(d1,d2);
end;

class operator TSHA2Digest.Implicit(const d:TSHA2Digest):TSHA224Digest;
begin
  Result:=d.Digest224;
end;

class operator TSHA2Digest.Implicit(const d:TSHA2Digest):TSHA256Digest;
begin
  Result:=d.Digest256;
end;

class operator TSHA2Digest.Implicit(const d:TSHA2Digest):TSHA384Digest;
begin
  Result:=d.Digest384;
end;

class operator TSHA2Digest.Implicit(const d:TSHA2Digest):TSHA512Digest;
begin
  Result:=d.Digest512;
end;

class operator TSHA2Digest.Implicit(const d:TSHA224Digest):TSHA2Digest;
begin
  Result.Digest224:=d;
end;

class operator TSHA2Digest.Implicit(const d:TSHA256Digest):TSHA2Digest;
begin
  Result.Digest256:=d;
end;

class operator TSHA2Digest.Implicit(const d:TSHA384Digest):TSHA2Digest;
begin
  Result.Digest384:=d;
end;

class operator TSHA2Digest.Implicit(const d:TSHA512Digest):TSHA2Digest;
begin
  Result.Digest512:=d;
end;

procedure TSHA2.Init(Version:TSHA2Version);
begin
  SHA2Init(Ctx,Version);
end;

procedure TSHA2.Update(const Buf; Len:PtrUInt);
begin
  SHA2Update(Ctx,Buf,Len);
end;

procedure TSHA2.Update(P:Pointer; Len:PtrUInt);
begin
  if P<>nil then
    SHA2Update(Ctx,P^,Len);
end;

procedure TSHA2.Final(out Digest:TSHA2Digest);
begin
  SHA2Final(Ctx,Digest);
end;

function TSHA2.Final:TSHA2Digest;
begin
  SHA2Final(Ctx,Result);
end;

class function TSHA2.HashBuffer(const Buf; Len:PtrUInt; Version:TSHA2Version):TSHA2Digest;
begin
  Result:=SHA2Buffer(Buf,Len,Version);
end;

class function TSHA2.HashString(const S:RawByteString; Version:TSHA2Version):TSHA2Digest;
begin
  Result:=SHA2Buffer(S[1],Length(S),Version);
end;

end.
