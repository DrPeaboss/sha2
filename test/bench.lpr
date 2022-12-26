program bench;

uses
  SysUtils,Classes,
  sha2;

const
  BUFSIZE = 1024*1024*512;

var
  ms:TMemoryStream;
  t:QWord;
  res:TSHA2Digest;
begin
  ms:=TMemoryStream.Create;
  ms.SetSize(BUFSIZE);
  FillChar(ms.Memory^,ms.Size,1);

  Writeln('Buffer size is ',BUFSIZE,' bytes (',BUFSIZE div (1024*1024),' MiB)');

  // 08bb5ac4e56c52caeaae8a376628afd19a71296242f8fac36cd0ed14a6194e1d
  t:=GetTickCount64;
  res:=Sha2Buffer(ms.Memory^,ms.Size,Sha256);
  t:=GetTickCount64-t;
  Writeln('SHA256 result: ',res.ToString());
  Writeln('SHA256 use ',t,' ms');

  // 918c1509a27b66728889a6fe29c002939435c3606e3d5a6b0f4c639eaa0b2193ba8b429c57650b42f75afa23db00b5fea95cb26eb55945f70ee0ac59445eca17
  t:=GetTickCount64;
  res:=Sha2Buffer(ms.Memory^,ms.Size,Sha512);
  t:=GetTickCount64-t;
  Writeln('SHA512 result: ',res.ToString());
  Writeln('SHA512 use ',t,' ms');

  ms.Free;
  Readln;
end.

