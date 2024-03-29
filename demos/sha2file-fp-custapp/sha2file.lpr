{ This project use CustApp unit to handle parameters, it's a cross-platform way,
  but is not very good for our custom parameter format.
  I recommend to use the project in sha2file-fp directory.
}

program sha2file;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils, CustApp,
  sha2;

type

  { TSHA2File }

  TSHA2File = class(TCustomApplication)
  private
    FFileName:String;
    FFlags:TSha2Versions;
    procedure DoSha2;
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
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
  Q:Boolean;
begin
  ctx:=[];
  Q:=HasOption('q','quiet');
  len:=0;
  for flag in FFlags do
  begin
    SetLength(ctx,len+1);
    Sha2Init(ctx[len],flag);
    Inc(len);
  end;
  FHandle:=FileOpen(FFileName,fmShareDenyNone);
  GetMem(buf,BufSize);
  TotalSize:=FileSeek(FHandle,Int64(0),fsFromEnd);
  FileSeek(FHandle,0,fsFromBeginning);
  ReadSize:=0;
  repeat
    len:=FileRead(FHandle,buf^,BufSize);
    if len>0 then
    begin
      ReadSize:=ReadSize+len;
      for i:=0 to Length(ctx)-1 do
        Sha2Update(ctx[i],buf^,len);
      if not Q then
        Write('Please wait [',ReadSize/TotalSize*100:2:2,'%] ...'#13);
    end;
  until len<BufSize;

  for i:=0 to Length(ctx)-1 do
  begin
    Sha2Final(ctx[i],digest);
    Writeln(Sha2VersionToString(digest.Version),': ',Sha2Print(digest));
  end;

  Freemem(buf);
  FileClose(FHandle);
end;

procedure TSHA2File.DoRun;
var
  ErrorMsg:String;
  NonOptions:TStringArray;
  NOLen:SizeInt;
  t1,t2:TTimeStamp;
begin
  ErrorMsg:=CheckOptions('hqas1234568',
    'help quiet sha224 sha256 sha384 sha512 sha512/224 sha512/256 all');
  if ErrorMsg<>'' then begin
    Writeln(ErrorMsg);
    Terminate;
    Exit;
  end;

  if HasOption('h','help') then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  NonOptions:=GetNonOptions('hqas1234568',
    ['help','quiet','sha224','sha256','sha384','sha512','sha512/224','sha512/256','all']);
  NOLen:=Length(NonOptions);
  if NOLen>0 then
  begin
    FFileName:=NonOptions[NOLen-1];
    if NOLen>1 then
      Writeln('Only Support One FileName, Use "',FFileName,'"');
    if not FileExists(FFileName) then
    begin
      Writeln('Can''t Open File "',FFileName,'"');
      Terminate;
      Exit;
    end;
    if HasOption('a','all') then
    begin
      FFlags:=[SHA2_224,SHA2_256,SHA2_384,SHA2_512,SHA2_512_224,SHA2_512_256]
    end else
    begin
      if HasOption('sha224') or HasOption('s224') then
        Include(FFlags,SHA2_224);
      if HasOption('sha256') or HasOption('s256') then
        Include(FFlags,SHA2_256);
      if HasOption('sha384') or HasOption('s384') then
        Include(FFlags,SHA2_384);
      if HasOption('sha512') or HasOption('s512') then
        Include(FFlags,SHA2_512);
      if HasOption('sha512/224') or HasOption('s524') then
        Include(FFlags,SHA2_512_224);
      if HasOption('sha512/256') or HasOption('s556') then
        Include(FFlags,SHA2_512_256);
      if FFlags=[] then
      begin
        FFlags:=[SHA2_256];
        if not HasOption('q','quiet') then
          Writeln('Hint: No options, use SHA256 default');
      end;
    end;
{$Ifdef CPUX86}
    if not HasOption('q','quiet') and (FFlags * [SHA2_384,SHA2_512,SHA2_512_224,SHA2_512_256]<>[]) then
      Writeln('Hint: SHA384, SHA512, SHA512/224 or SHA512/256 is slow for i386, use x64 instead');
{$Endif}
    t1:=DateTimeToTimeStamp(Now);
    DoSha2;
    t2:=DateTimeToTimeStamp(Now);
    if not HasOption('q','quiet') then
      Writeln('Total use ',t2.Time-t1.Time,' ms');
    Terminate;
    Exit;
  end;

  WriteHelp;
  Terminate;
end;

constructor TSHA2File.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
end;

destructor TSHA2File.Destroy;
begin
  inherited Destroy;
end;

procedure TSHA2File.WriteHelp;
begin
  Writeln('Usage: ',ExtractFileName(ExeName),' [options] <FileName> [options]');
  Writeln(' If only input FileName, use SHA256 default');
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
  Application: TSHA2File;
begin
  Application:=TSHA2File.Create(nil);
  Application.Title:='SHA2File';
  Application.Run;
  Application.Free;
end.

