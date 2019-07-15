Dim gChartHeight As Integer
Dim gChartWidth As Integer
Dim gColumnCount

Sub AddFields(table As String, length As String, fieldList As Collection, outSheet As String)
    Sheets(outSheet).Select
    hPos = 0
    For Each Chart In ActiveSheet.Shapes
        bottom = Chart.Top + Chart.Height
        If bottom > hPos Then
            hPos = Chart.Top + Chart.Height
        End If
    Next
    
    ActiveSheet.Shapes.AddChart.Select
    ActiveChart.ChartType = xlLine
    ActiveChart.ChartArea.Left = 0
    ActiveChart.ChartArea.Top = hPos
    ActiveChart.ChartArea.Height = gChartHeight
    
    ActiveChart.ChartArea.Width = gChartWidth
    
    i = 1
    While i <= fieldList.Count
        col = fieldList(i)
        
        'convert network rate value from "Mbps" string to pure number
        Value = Sheets(table).Cells(2, col).Value
        If InStr(Value, "Mbps") <> 0 Then
            For j = 2 To length
                Value = Sheets(table).Cells(j, col).Value
                If InStr(Value, "Mbps") <> 0 Then
                    Value = Split(Value, "M")
                    Sheets(table).Cells(j, col).Value = Value(0)
                End If
            Next j
        End If
        
        ActiveChart.SeriesCollection.Add Source:=Sheets(table).Range(col + "1:" + col + length), SeriesLabels:=True
        i = i + 1
    Wend
End Sub

Sub Title2Field(table As String, title As String, length As String, out)
    'convert field title to field address
    Sheets(table).Select
    
    'calculate column count
    If gColumnCount = 0 Then
        For i = 1 To Columns.Count
            If Cells(1, i).Value = "" Then
                gColumnCount = i
                Exit For
            End If
        Next i
    End If
    
    Dim newtitle As String
    
    For i = 1 To gColumnCount
        field = Cells(1, i).Value
        If field = title Then
            'convert cpu#idle to cpu#occupy
            If title = "cpu#idle" Then
                newtitle = "cpu#occupy"
                out = gColumnCount + 7
                Cells(1, CInt(out)).Value = newtitle
                For k = 2 To length
                    If Cells(k, i).Value <> "" Then
                        Cells(k, CInt(out)).Value = 100 - CInt(Cells(k, i).Value)
                    Else
                        Cells(k, CInt(out)).Value = ""
                    End If
                Next k
                out = Split(Cells(1, CInt(out)).Address, "$")(1)
            Else
                out = i
                out = Split(Cells(1, i).Address, "$")(1)
            End If
            
            Exit Sub
        End If
    Next i
    
End Sub

Sub AddChart(table As String, length As String, outSheet As String, fieldArray)
    Dim out As String
    Dim col As String
    Dim mylist As New Collection
    
    i = 0
    While i <= UBound(fieldArray)
        col = fieldArray(i)
        Title2Field table, col, length, out
        mylist.Add (out)
        i = i + 1
    Wend

    AddFields table, length, mylist, outSheet
End Sub

Sub AddNode(srcSheet As String, dstSheet As String, srcCount As String, chartList)
    Sheets.Add.Name = dstSheet
    
    i = 0
    While i <= UBound(chartList)
        myarray = chartList(i)
        AddChart srcSheet, srcCount, dstSheet, myarray
        i = i + 1
    Wend

    
End Sub
Sub Main()
    gColumnCount = 0
    gChartHeight = 700
    gChartWidth = 2000
    
    'chartList = Array( _
                        Array("Tcp#CurrEstab", "Tcp#ActiveOpens", "Tcp#PassiveOpens"), _
                        Array("ESTAB#Local.rto.eq.avg", "ESTAB#Local.rto.eq.min", "ESTAB#Local.rto.eq.max"), _
                        Array("ESTAB#Local.retrans.eq.avg", "ESTAB#Local.retrans.eq.min", "ESTAB#Local.retrans.eq.max"), _
                        Array("ESTAB#Local.w.eq.avg", "ESTAB#Local.w.eq.min", "ESTAB#Local.w.eq.max"), _
                        Array("ESTAB#Local.cwnd.eq.max", "ESTAB#Local.cwnd.eq.min", "ESTAB#Local.cwnd.eq.avg"), _
                        Array("Tcp#TCPPureAcks", "Tcp#TCPHPAcks", "Tcp#TW"), _
                        Array("Tcp#DelayedACKs", "Tcp#DelayedACKLost"), _
                        Array("ct#new-ct#delete"), _
                        Array("Tcp#TCPTimeouts", "Tcp#TCPSpuriousRTOs", "Tcp#TCPRetransFail") _
                        )
     'chartList = Array( _
                        Array("Tcp#CurrEstab", "Tcp#ActiveOpens", "Tcp#PassiveOpens", "dSYN#pkts", "uSYN#pkts", "ESTAB#Local.count", "ESTAB#Peer.count") _
                        )
     chartList = Array( _
                        Array("Tcp#PassiveOpens", "dSYN#pkts", "ESTAB#Local.count"), _
                        Array("dev#t_byte", "cpu#idle", "cpu#user", "cpu#sys"), _
                        Array("Tcp#TCPSlowStartRetrans", "Tcp#TCPLossUndo", "Tcp#OutRsts"), _
                        Array("ESTAB#Local.rtt.eq.avg", "ESTAB#Local.rtt.eq.min", "ESTAB#Local.rtt.eq.max"), _
                        Array("ESTAB#Peer.rto.eq.avg", "ESTAB#Peer.rto.eq.min", "ESTAB#Peer.rto.eq.max"), _
                        Array("ESTAB#Local.rto.eq.avg", "ESTAB#Local.rto.eq.min", "ESTAB#Local.rto.eq.max"), _
                        Array("ESTAB#Peer.w.eq.avg", "ESTAB#Peer.w.eq.min", "ESTAB#Peer.w.eq.max"), _
                        Array("ESTAB#Local.w.eq.avg", "ESTAB#Local.w.eq.min", "ESTAB#Local.w.eq.max") _
                        )
    
    Count = Sheets.Count
    i = 1
    While i <= Count
        j = 0
        mycharts = Array("chart_55", "chart_56")
        Do While j <= UBound(mycharts)
            If Sheets(i).Name = mycharts(j) Then
                Sheets(i).Delete
                Count = Count - 1
                i = i - 1
                Exit Do
            End If
            j = j + 1
        Loop
        i = i + 1
    Wend
    
    
    'Sheets("chart_55").Delete
    'Sheets("chart_56").Delete
    
    AddNode "55", "chart_55", "350", chartList
    AddNode "56", "chart_56", "887", chartList
    
End Sub

