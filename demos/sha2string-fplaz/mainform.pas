unit mainform;

{$Mode objfpc}{$H+}

interface

uses
  SysUtils,Classes,Graphics,Controls,Forms,StdCtrls;

type
  TForm1 = class(TForm)
    MemoInput: TMemo;
    MemoOutput: TMemo;
    RadioButtonL: TRadioButton;
    RadioButtonU: TRadioButton;
    procedure MemoInputChange(Sender: TObject);
    procedure RadioButtonUClick(Sender: TObject);
    procedure RadioButtonLClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
    FLowerCase:Boolean;
    procedure GetHash;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

uses
  sha2;

{$R *.lfm}

function SHA2VersionToString(v:TSHA2Version):String;
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

procedure TForm1.FormCreate(Sender: TObject);
begin
  FLowerCase:=True;
end;

procedure TForm1.GetHash;
var
  sha:TSHA2Version;
begin
  MemoOutput.Lines.Clear;
  if MemoInput.Lines.Text<>'' then
  begin
    for sha := SHA2_224 to SHA2_512_256 do
    begin
      MemoOutput.Lines.Add(SHA2VersionToString(sha)+': ');
      MemoOutput.Lines.Add(TSHA2.HashString(UTF8Encode(MemoInput.Lines.Text),sha).ToString(FLowerCase));
      MemoOutput.Lines.Add('');
    end;
  end;
end;

procedure TForm1.MemoInputChange(Sender: TObject);
begin
  GetHash;
end;

procedure TForm1.RadioButtonLClick(Sender: TObject);
begin
  FLowerCase:=True;
  GetHash;
end;

procedure TForm1.RadioButtonUClick(Sender: TObject);
begin
  FLowerCase:=False;
  GetHash;
end;

end.
