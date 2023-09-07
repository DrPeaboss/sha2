program bench;

uses
  SysUtils,Classes,
  sha2;

const
  BUFSIZE = 1024*1024*1024;

var
  ms:TMemoryStream;
  t,time:QWord;
  res:TSHA2Digest;
  i:Integer;
begin
  ms:=TMemoryStream.Create;
  ms.SetSize(BUFSIZE);
  FillChar(ms.Memory^,ms.Size,1);
  Writeln('Buffer size is ',BUFSIZE,' bytes (',BUFSIZE/(1024*1024):2:2,' MiB)');

  time:=0;
  for i:=0 to 9 do
  begin
    t:=GetTickCount64;
    res:=Sha2Buffer(ms.Memory^,ms.Size,SHA2_256);
    t:=GetTickCount64-t;
    time:=time+t;
    Writeln('Pass ',i,', time: ',t,' ms');
  end;
  // 4eb29e7b79c0ad1e578803c357b47d9cdfc1a9c23b293bf1ca4f9d81d08bfadf
  Writeln('Result: ',res.ToString());
  Writeln('Total time: ',time,' ms');
  Writeln('SHA256 avg speed: ',10*BUFSIZE/1024/1024/(time/1000):2:2,' MiB/s');

  time:=0;
  for i:=0 to 9 do
  begin
    t:=GetTickCount64;
    res:=Sha2Buffer(ms.Memory^,ms.Size,SHA2_512);
    t:=GetTickCount64-t;
    time:=time+t;
    Writeln('Pass ',i,', time: ',t,' ms');
  end;
  // 9eb37ab793089030761a888a130690300028fcb03bffe9fac218a62a7db541c0026bb79548c06842307b73f9d06eee8df78b4c00ac2de6a06666963dbc1ef966
  Writeln('Result: ',res.ToString());
  Writeln('Total time: ',time,' ms');
  Writeln('SHA512 avg speed: ',10*BUFSIZE/1024/1024/(time/1000):2:2,' MiB/s');

  ms.Free;
end.

