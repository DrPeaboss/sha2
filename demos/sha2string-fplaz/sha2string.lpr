program sha2string;

{$MODE Objfpc}{$H+}

uses
{$IFDEF UNIX}
  cthreads,
{$ENDIF}
  Interfaces,
  Forms,
  mainform;

{$R *.res}

begin
  RequireDerivedFormResource := True;
{$ifdef WINDOWS}
  Application.{%H-}MainFormOnTaskBar:=True;  // ignore the warning
{$endif}
  Application.Scaled:=True;
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
