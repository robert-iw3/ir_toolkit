$token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
Invoke-RestMethod -Uri "https://slack.com/api/chat.postMessage" -Headers @{Authorization="Bearer $token"}
