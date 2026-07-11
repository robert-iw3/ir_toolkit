$uri = "https://contoso.webhook.office.com/webhookb2/11111111-2222-3333-4444-555555555555@tenant/IncomingWebhook/abcdef/12345"
$body = '{"@type":"MessageCard","@context":"http://schema.org/extensions","text":"beacon"}'
Invoke-RestMethod -Uri $uri -Method Post -Body $body
