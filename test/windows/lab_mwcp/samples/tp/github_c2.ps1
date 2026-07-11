$token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
Invoke-RestMethod -Uri "https://api.github.com/gists" -Headers @{Authorization="token $token"} -Method Post
