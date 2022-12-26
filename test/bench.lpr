program bench;

uses
  SysUtils,Classes,
  sha2;

const
  BUFSIZE = 1024*1024*512;

var
  ms:TMemoryStream;
  t:QWord;
begin
  ms:=TMemoryStream.Create;
  ms.SetSize(BUFSIZE);

  Writeln('Buffer size is ',BUFSIZE,' bytes (',BUFSIZE div (1024*1024),' MiB)');

  t:=GetTickCount64;
  Sha2Buffer(ms.Memory^,ms.Size,Sha256);
  t:=GetTickCount64-t;
  Writeln('SHA256 use ',t,' ms');

  t:=GetTickCount64;
  Sha2Buffer(ms.Memory^,ms.Size,Sha512);
  t:=GetTickCount64-t;
  Writeln('SHA512 use ',t,' ms');

  ms.Free;
  Readln;
end.

