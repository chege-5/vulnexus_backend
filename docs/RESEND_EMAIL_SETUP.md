# Resend transactional email

VulNexus sends account and optional product emails directly through the official Resend Python SDK after the related database transaction commits. Delivery failures are contained and never roll back account, scan, or subscription state.

## Railway production variables

```env
EMAIL_ENABLED=true
RESEND_API_KEY=re_replace_in_railway_only
EMAIL_FROM_NAME=VulNexus Security Platform
EMAIL_FROM_ADDRESS=security@your-verified-domain.example
EMAIL_REPLY_TO=support@your-verified-domain.example
FRONTEND_URL=https://vulnexus.vercel.app
EMAIL_SEND_TIMEOUT_SECONDS=20
EMAIL_VERIFICATION_COOLDOWN_SECONDS=60
```

Verify the sender domain in Resend before enabling mail. `EMAIL_FROM_ADDRESS` must use that domain, while `EMAIL_FROM_NAME` controls the inbox display name. `EMAIL_REPLY_TO` is independent and does not change the branded From identity. The Resend test sender is only appropriate where Resend explicitly permits development testing. Never put the API key in a Vite variable, repository file, browser request, or log.

Set `EMAIL_ENABLED=false` locally to skip delivery safely. For a local Resend test, set `EMAIL_ENABLED=true`, a Resend-permitted testing sender, `FRONTEND_URL=http://localhost:5173`, and a test API key in an uncommitted `.env`.

## Manual verification

1. Register an email/password account.
2. Open the verification-code page, enter the six-digit code from the email, and confirm it sends the user to the dashboard.
3. Confirm the welcome email arrives once.
4. Use forgot-password, enter the six-digit reset code, set a new password, and confirm it sends the user to the dashboard with a password-changed alert.

If delivery fails, application data still commits. Check API or scan-worker logs for the event name and Resend message ID only; codes, keys, recipients, and message bodies are intentionally not logged. An unverified sender/domain causes Resend to reject delivery. An invalid `FRONTEND_URL` prevents safe link construction. Production startup rejects enabled mail without Resend credentials, sender, or an HTTPS frontend URL.
