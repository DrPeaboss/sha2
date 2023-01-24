program bench;

uses
  SysUtils,Classes,
  sha2;

const
  BUFSIZE = 1024*1024*1024;

var
  ms:TMemoryStream;
  t:QWord;
  res:TSHA2Digest;
begin
  ms:=TMemoryStream.Create;
  ms.SetSize(BUFSIZE);
  FillChar(ms.Memory^,ms.Size,1);

  Writeln('Buffer size is ',BUFSIZE,' bytes (',BUFSIZE div (1024*1024),' MiB)');

  // 4eb29e7b79c0ad1e578803c357b47d9cdfc1a9c23b293bf1ca4f9d81d08bfadf
  t:=GetTickCount64;
  res:=Sha2Buffer(ms.Memory^,ms.Size,SHA2_256);
  t:=GetTickCount64-t;
  Writeln('SHA256 result: ',res.ToString());
  Writeln('SHA256 use ',t,' ms');
  Writeln('SHA256 speed: ',BUFSIZE/1024/1024/(t/1000):2:2,' MiB/s');

  // 9eb37ab793089030761a888a130690300028fcb03bffe9fac218a62a7db541c0026bb79548c06842307b73f9d06eee8df78b4c00ac2de6a06666963dbc1ef966
  t:=GetTickCount64;
  res:=Sha2Buffer(ms.Memory^,ms.Size,SHA2_512);
  t:=GetTickCount64-t;
  Writeln('SHA512 result: ',res.ToString());
  Writeln('SHA512 use ',t,' ms');
  Writeln('SHA512 speed: ',BUFSIZE/1024/1024/(t/1000):2:2,' MiB/s');

  ms.Free;
  Readln;
end.

