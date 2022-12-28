object Form1: TForm1
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = 'SHA2 String'
  ClientHeight = 523
  ClientWidth = 631
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 16
  object MemoInput: TMemo
    Left = 8
    Top = 8
    Width = 617
    Height = 137
    ScrollBars = ssVertical
    TabOrder = 0
    OnChange = MemoInputChange
  end
  object MemoOutput: TMemo
    Left = 8
    Top = 174
    Width = 617
    Height = 341
    ReadOnly = True
    TabOrder = 1
  end
  object RadioButtonL: TRadioButton
    Left = 16
    Top = 151
    Width = 113
    Height = 17
    Caption = 'LowerCase'
    Checked = True
    TabOrder = 2
    TabStop = True
    OnClick = RadioButtonLClick
  end
  object RadioButtonU: TRadioButton
    Left = 143
    Top = 151
    Width = 113
    Height = 17
    Caption = 'UpperCase'
    TabOrder = 3
    OnClick = RadioButtonUClick
  end
end
