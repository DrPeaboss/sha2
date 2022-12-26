program sha2file;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  sha2;

type
  TSHA2File = class
  private
    FFileName:String;
    FFlags:TSha2Versions;
    FQuiet:Boolean;
    procedure DoSha2;
    function ParseParam(index:Integer;const arg:String):Boolean;
  public
    procedure Run;
    procedure WriteHelp;
  end;


function Sha2VersionToString(v:TSha2Version):String;
begin
  Result:='';
  case v of
    SHA2_224: Result:='SHA224';
    SHA2_256: Result:='SHA256';
    SHA2_384: Result:='SHA384';
    SHA2_512: Result:='SHA512';
    SHA2_512_224: Result:='SHA512/224';
    SHA2_512_256: Result:='SHA512/256';
  end;
end;

{ TSHA2File }

procedure TSHA2File.DoSha2;
const
  BufSize = 1024000;
var
  ctx:array of TSha2Context;
  digest:TSha2Digest;
  FHandle:THandle;
  buf:Pointer;
  len,i:Integer;
  flag:TSha2Version;
  ReadSize,TotalSize:Int64;
begin
  ctx:=[];
  len:=0;
  for flag in FFlags do
  begin
    SetLength(ctx,len+1);
    Sha2Init(ctx[len],flag);
    Inc(len);
  end;
  FHandle:=FileOpen(FFileName,fmShareDenyNone);
  GetMem(buf,BufSize);
  TotalSize:=FileSeek(FHandle,Int64(0),2);
  FileSeek(FHandle,0,0);
  ReadSize:=0;
  repeat
    len:=FileRead(FHandle,buf^,BufSize);
    if len>0 then
    begin
      ReadSize:=ReadSize+len;
      for i:=0 to Length(ctx)-1 do
        Sha2Update(ctx[i],buf^,len);
      if not FQuiet then
        Write('Please wait [',ReadSize/TotalSize*100:2:2,'%] ...'#13);
    end;
  until len<BufSize;

  for i:=0 to Length(ctx)-1 do
  begin
    Sha2Final(ctx[i],digest);
    Writeln(Sha2VersionToString(digest.Version),': ',digest.ToString());
  end;

  Freemem(buf);
  FileClose(FHandle);
end;

function TSHA2File.ParseParam(index:Integer;const arg: String): Boolean;
var
  param:String;
begin
  Result:=False;
  case arg[1] of
    '-':begin
      if Length(arg)=1 then
      begin
        Writeln('No option at position ',index);
        Exit;
      end;
      if arg[2]='-' then
      begin
        if Length(arg)=2 then
        begin
          Writeln('No option at position ',index);
          Exit;
        end;
        param:=Copy(arg,3,length(arg)-2);
        if param='help' then
        begin
          WriteHelp;
          Exit;
        end
        else if param='all' then
          FFlags:=[SHA2_224,SHA2_256,SHA2_384,SHA2_512,SHA2_512_224,SHA2_512_256]
        else if param='quiet' then
          FQuiet:=True
        else if param='sha224' then
          Include(FFlags,SHA2_224)
        else if param='sha256' then
          Include(FFlags,SHA2_256)
        else if param='sha384' then
          Include(FFlags,SHA2_384)
        else if param='sha512' then
          Include(FFlags,SHA2_512)
        else if param='sha512/224' then
          Include(FFlags,SHA2_512_224)
        else if param='sha512/256' then
          Include(FFlags,SHA2_512_256)
        else
        begin
          Writeln('Invalid parameter: ',arg,' at position ',index);
          Exit;
        end;
        Exit(True);
      end;

      case arg[2] of

          'h':begin
            if Length(arg)>2 then
            begin
              Writeln('Invalid parameter: ',arg,' at position ',index);
              Exit;
            end;
            WriteHelp;
            Exit;
          end;

          'a':begin
            if Length(arg)>2 then
            begin
              Writeln('Invalid parameter: ',arg,' at position ',index);
              Exit;
            end;
            FFlags:=[SHA2_224,SHA2_256,SHA2_384,SHA2_512,SHA2_512_224,SHA2_512_256];
          end;

          'q':begin
            if Length(arg)>2 then
            begin
              Writeln('Invalid parameter: ',arg,' at position ',index);
              Exit;
            end;
            FQuiet:=True;
          end;

          's':begin
            param:=Copy(arg,3,Length(arg)-2);
            if param='224' then
              Include(FFlags,SHA2_224)
            else if param='256' then
              Include(FFlags,SHA2_256)
            else if param='384' then
              Include(FFlags,SHA2_384)
            else if param='512' then
              Include(FFlags,SHA2_512)
            else if param='524' then
              Include(FFlags,SHA2_512_224)
            else if param='556' then
              Include(FFlags,SHA2_512_256)
            else
            begin
              Writeln('Invalid parameter: ',arg,' at position ',index);
              Exit;
            end;
          end;

          else
          begin
            Writeln('Invalid parameter: ',arg,' at position ',index);
            Exit;
          end;
      end;
    end;

    else
    begin
      if not FQuiet and (FFileName<>'') then
        Writeln('Hint: Only support one file, change "',FFileName,'" to "',arg,'"');
      FFileName:=arg;
    end;
  end;
  Result:=True;
end;

procedure TSHA2File.Run;
var
  i:Integer;
  t1,t2:TTimeStamp;
begin
  if ParamCount>0 then
  begin
    for i := 1 to ParamCount do
      if not ParseParam(i,ParamStr(i)) then
        Exit;
    if FFileName='' then
    begin
      Writeln('Error: No any file input');
      Exit;
    end;
    if Not FileExists(FFileName) then
    begin
      Writeln('Error: Can''t open file "',FFileName,'"');
      Exit;
    end;
    if FFlags=[] then
    begin
      if Not FQuiet then
        Writeln('Hint: No options, use SHA256 default');
      FFlags:=[SHA2_256];
    end;
{$Ifdef CPUX86}
    if Not FQuiet and (FFLags*[SHA2_384,SHA2_512,SHA2_512_224,SHA2_512_256]<>[]) then
      Writeln('Hint: SHA384, SHA512, SHA512/224 or SHA512/256 is slow for i386, use x64 instead');
{$Endif}
    t1:=DateTimeToTimeStamp(Now);
    DoSha2;
    t2:=DateTimeToTimeStamp(Now);
    if not FQuiet then
      Writeln('Total use ',t2.Time-t1.Time,' ms');
    Exit;
  end;

  WriteHelp;
end;

procedure TSHA2File.WriteHelp;
begin
  Writeln('Usage: ',ExtractFileName(ParamStr(0)),' [options] <FileName> [options]');
  Writeln(' If only input FileName, use sha256 default');
  Writeln('  -s224, --sha224'#9'Add SHA224 output');
  Writeln('  -s256, --sha256'#9'Add SHA256 output');
  Writeln('  -s384, --sha384'#9'Add SHA384 output');
  Writeln('  -s512, --sha512'#9'Add SHA512 output');
  Writeln('  -s524, --sha512/224'#9'Add SHA512/224 output');
  Writeln('  -s556, --sha512/256'#9'Add SHA512/256 output');
  Writeln('  -a, --all'#9#9'Use all SHA2 algorithms');
  Writeln('  -q, --quiet'#9#9'Do not show progress and hints');
  Writeln;
  Writeln('  -h, --help'#9#9'Show this help');
end;

var
  sha2f:TSHA2File;
begin
  try
    sha2f:=TSHA2File.Create;
    try
      sha2f.Run;
    finally
      sha2f.Free;
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
