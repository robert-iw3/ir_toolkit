$sheet = "https://sheets.googleapis.com/v4/spreadsheets/1a2b3c4d5e6f7g8h9i"
$key = "AIzaSyD1234567890abcdefghijklmnopqrstuv"
Invoke-RestMethod -Uri "$sheet/values/A1?key=$key"
