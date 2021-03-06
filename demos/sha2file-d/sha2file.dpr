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
    Sha224: Result:='Sha224';
    Sha256: Result:='Sha256';
    Sha384: Result:='Sha384';
    Sha512: Result:='Sha512';
    Sha512_224: Result:='Sha512/224';
    Sha512_256: Result:='Sha512/256';
  end;
end;

{ TSHA2File }

procedure TSHA2File.DoSha2;
const
  BufSize = 1024000;
var
  ctx:array[Sha224..Sha512_256] of TSha2Context;
  digest:TSha2Digest;
  FHandle:THandle;
  buf:Pointer;
  len:Integer;
  flag:TSha2Version;
  ReadSize,TotalSize:Int64;
begin
  ctx[Sha224]:=Default(TSha2Context); // make the compiler shut up
  for flag in FFlags do
    Sha2Init(ctx[flag],flag);
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
      for flag in FFlags do
        Sha2Update(ctx[flag],buf^,len,flag);
      if not FQuiet then
        Write('Please wait [',ReadSize/TotalSize*100:2:2,'%] ...'#13);
    end;
  until len<BufSize;

  for flag in FFlags do
  begin
    Sha2Final(ctx[flag],flag,digest);
    Writeln(Sha2VersionToString(flag),': ',Sha2Print(digest,flag));
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
          FFlags:=[Sha224,Sha256,Sha384,Sha512,Sha512_224,Sha512_256]
        else if param='quiet' then
          FQuiet:=True
        else if param='sha224' then
          Include(FFlags,Sha224)
        else if param='sha256' then
          Include(FFlags,Sha256)
        else if param='sha384' then
          Include(FFlags,Sha384)
        else if param='sha512' then
          Include(FFlags,Sha512)
        else if param='sha512/224' then
          Include(FFlags,Sha512_224)
        else if param='sha512/256' then
          Include(FFlags,Sha512_256)
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
            FFlags:=[Sha224,Sha256,Sha384,Sha512,Sha512_224,Sha512_256];
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
              Include(FFlags,Sha224)
            else if param='256' then
              Include(FFlags,Sha256)
            else if param='384' then
              Include(FFlags,Sha384)
            else if param='512' then
              Include(FFlags,Sha512)
            else if param='524' then
              Include(FFlags,Sha512_224)
            else if param='556' then
              Include(FFlags,Sha512_256)
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
      FFlags:=[Sha256];
    end;
{$Ifdef CPUX86}
    if Not FQuiet and (FFLags*[Sha384,Sha512,Sha512_224,Sha512_256]<>[]) then
      Writeln('Hint: Sha384, Sha512, Sha512/224 or Sha512/256 is slow for i386, use x64 instead');
{$Endif}
    DoSha2;
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
