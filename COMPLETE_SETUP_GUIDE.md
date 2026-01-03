# Complete Implementation Checklist & Configuration Guide

## ✅ Implementation Status

### Code Implementation
- ✅ Raw body middleware added to server.js
- ✅ Webhook endpoint `/api/paystack/webhook` created
- ✅ Signature verification implemented (HMAC-SHA512)
- ✅ Duplicate payment prevention added
- ✅ Wallet crediting logic implemented
- ✅ Payment recording with webhook source tracking
- ✅ SMS notification integration (async)
- ✅ In-app notification creation
- ✅ Webhook event logging
- ✅ Error handling and recovery
- ✅ No syntax errors (verified)

### Documentation
- ✅ PAYSTACK_WEBHOOK_SETUP.md (complete technical guide)
- ✅ WEBHOOK_QUICK_START.md (quick reference)
- ✅ WEBHOOK_IMPLEMENTATION_SUMMARY.md (overview)
- ✅ CODE_IMPLEMENTATION_DETAILS.md (code reference)
- ✅ WEBHOOK_ARCHITECTURE.md (visual diagrams)
- ✅ This file: COMPLETE_SETUP_GUIDE.md

---

## 📋 Pre-Configuration Checklist

Before configuring the webhook in Paystack, verify:

### Server Configuration
- [ ] Server is running: `npm start` or `node server.js`
- [ ] Server is accessible from internet (not localhost)
- [ ] HTTPS/SSL certificate is valid
- [ ] `.env` file has correct values:
  - [ ] `PAYSTACK_SECRET_KEY` = your Paystack secret key
  - [ ] `PAYSTACK_PUBLIC_KEY` = your Paystack public key
  - [ ] `BASE_URL` = `https://datasell.store` (or your domain)
  - [ ] `MNOTIFY_API_KEY` = your mNotify API key (for SMS)
- [ ] Server is running on port accessible from internet
- [ ] Database (Firebase) is properly configured

### Paystack Account
- [ ] Paystack account created and verified
- [ ] API keys generated (Secret + Public)
- [ ] Account is in Live mode (not Test mode) if using production
- [ ] Correct keys copied to `.env`

### Domain
- [ ] Domain points to your server
- [ ] Domain has valid SSL certificate
- [ ] Domain can be accessed from internet
- [ ] No firewall blocking webhook requests

---

## 🚀 Step-by-Step Configuration (5 minutes)

### Step 1: Log into Paystack Dashboard
```
1. Go to https://dashboard.paystack.com
2. Sign in with your email and password
3. You're now in the Paystack dashboard
```

### Step 2: Navigate to API Keys & Webhooks
```
1. Look for "Settings" in the sidebar or top menu
2. Click "API Keys & Webhooks"
3. OR go directly to: https://dashboard.paystack.com/settings/developers
```

### Step 3: Find the Webhooks Section
```
You should see:
┌─────────────────────────────────┐
│ API Keys                        │
│ [Your Secret Key]               │
│ [Your Public Key]               │
│                                 │
│ Webhooks                        │
│ [Add Webhook] button            │
└─────────────────────────────────┘
```

### Step 4: Add Webhook URL
```
1. Click "Add Webhook" button
2. In the URL field, enter:
   https://datasell.store/api/paystack/webhook

   OR if using different domain:
   https://yourdomain.com/api/paystack/webhook

3. Copy the exact URL above
4. Click "Add" or "Save"
```

### Step 5: Select Events
```
In the Events section, make sure these are CHECKED:
✓ charge.success

Optional (for monitoring):
□ charge.failed
□ charge.dispute.create
□ customer.identification
□ transfer.success

Save the webhook configuration
```

### Step 6: Verify Webhook Status
```
After saving, you should see:
┌─────────────────────────────────────────┐
│ Webhook Configuration                   │
│                                         │
│ URL: [Your webhook URL]                │
│ Status: ✓ ACTIVE                       │
│ Events: charge.success                 │
│                                         │
│ Last Attempt: [timestamp]              │
│ Test Webhook: [Send Test]              │
└─────────────────────────────────────────┘

✓ Green/ACTIVE status = Configuration successful!
✗ Red/Inactive = Something wrong, check URL and domain
```

---

## 🧪 Testing Your Webhook Setup

### Test Method 1: Make a Real Test Payment (Recommended)
```
1. Go to your DataSell app (https://datasell.store)
2. Log in as a test user
3. Click "Add Funds" or go to Wallet
4. Enter test amount (e.g., 10 GHS)
5. Click "Pay Now"
6. You'll be taken to Paystack

USING TEST CARD:
  Card Number: 5531 8866 7264 6917
  Expiry: 05/25
  CVV: 123
  OTP (when asked): 123456

7. Complete the payment
8. Watch for:
   - You get redirected back to DataSell
   - Confirmation page shows
   - You receive SMS shortly after
   - Wallet balance increases
```

### Test Method 2: Check Server Logs
```
After payment, in your server console, look for:

🔔 Webhook event received: charge.success
📋 Webhook data: {
  event: 'charge.success',
  reference: 'abc123...',
  amount: 50000,
  userId: 'user...',
  ...
}
✅ Wallet credited via webhook: [userId] received ₵[amount]
✅ Webhook processed successfully for reference: abc123...

These messages indicate:
✓ Webhook was received
✓ Signature verified
✓ Wallet was credited
✓ Processing completed
```

### Test Method 3: Verify Database Changes
```
In Firebase Console (https://console.firebase.google.com):

1. Check /users/{userId}/walletBalance
   - Should show increased amount ✓

2. Check /payments
   - Should show new payment record ✓
   - Should include source: 'webhook' ✓

3. Check /notifications
   - Should show new notification ✓

4. Check /webhook_logs
   - Should show processed event ✓
   - Status should be 'processed' ✓
```

### Expected Results After Payment
```
IMMEDIATE (within seconds):
✅ Server logs show webhook received and processed
✅ Wallet balance updates in Firebase

SHORT TERM (within 30 seconds):
✅ SMS notification arrives
✅ In-app notification appears
✅ Payment recorded in /payments

USER SEES:
1. Redirect to confirmation page (fast)
2. SMS "Your DataSell has been credited..." (5-30 seconds)
3. Wallet balance updated in app (real-time)
4. In-app notification badge/alert
```

---

## ✋ Troubleshooting During Setup

### Issue: Webhook shows as "Inactive" in Paystack
**Cause**: URL is incorrect or unreachable
**Solution**:
1. Verify URL is exactly: `https://datasell.store/api/paystack/webhook`
2. Remove trailing slashes
3. Ensure domain is correct (not localhost, not http://)
4. Try accessing the URL directly in browser (you'll get error, that's OK)
5. If you get a connection error, your server may not be accessible

### Issue: Webhook URL shows error when saving
**Cause**: Domain not accessible
**Solution**:
1. Verify server is running
2. Verify domain has valid SSL certificate
3. Verify firewall allows HTTPS requests from internet
4. Check that no reverse proxy is blocking webhook requests
5. Try accessing your domain from another browser

### Issue: Payment not credited after completing Paystack payment
**Cause**: Various possibilities
**Solution**:
1. Check server logs for error messages
2. Check webhook was received (look for 🔔 message)
3. If no webhook message, check Paystack webhook is active
4. If webhook message but error, check:
   - [ ] PAYSTACK_SECRET_KEY is correct
   - [ ] User ID in metadata
   - [ ] User exists in database
5. Check /webhook_logs in Firebase for error details

### Issue: "Invalid webhook signature" error in logs
**Cause**: PAYSTACK_SECRET_KEY is incorrect
**Solution**:
1. Go to Paystack Dashboard → Settings → API Keys & Webhooks
2. Copy your **SECRET KEY** (not public key)
3. Update it in your `.env` file
4. Restart server
5. Test again

### Issue: SMS not received after payment
**Cause**: mNotify not configured or API key wrong
**Solution**:
1. Check MNOTIFY_API_KEY in `.env`
2. Verify user has phone number in their profile
3. Check mNotify logs for failures
4. SMS failure doesn't affect wallet credit (webhook succeeds)

### Issue: No notifications in database
**Cause**: Different causes
**Solution**:
1. Check /notifications collection exists in Firebase
2. Verify webhook logs show "processed" status
3. Check server error logs for notification creation errors
4. Webhook succeeds even if notification fails

### Issue: Duplicate payments (wallet credited multiple times)
**Cause**: Should not happen, system prevents this
**Troubleshooting**:
1. Check /webhook_logs for duplicate attempts
2. If you see "Payment already processed" message, that's correct
3. Check payment amounts match (if not, different payments)
4. Contact support with details if genuinely duplicated

---

## 📊 Monitoring & Verification

### Daily Checks
```
□ Check server logs for any 🔔 webhook messages
□ Verify no ❌ error messages in logs
□ Check a few payments were processed successfully
□ Verify SMS notifications were sent
```

### Weekly Checks
```
□ Review /webhook_logs in Firebase
□ Check payment processing times (should be < 1 second)
□ Verify wallet balances are correct
□ Check for any error patterns
□ Verify Paystack webhook is still Active
```

### Monthly Checks
```
□ Review total payments processed via webhook
□ Check duplicate prevention statistics
□ Analyze any failed payments
□ Verify SMS delivery rates
□ Review notification creation rates
□ Update documentation if needed
```

### What to Monitor In Firebase

#### /webhook_logs
```
This collection tracks all webhook events:

✓ status: 'processed' = payment credited successfully
✗ status: 'failed' = something went wrong

Investigate any 'failed' entries:
- Check the error message
- Look for patterns (same error repeatedly?)
- Check user ID is valid
- Verify payment amount is correct
```

#### /payments
```
This collection stores payment records:

For webhook payments, look for:
- source: 'webhook' = processed automatically ✓
- source: 'callback' = processed manually
- source: undefined = old payments

Verify:
- Status is always 'success'
- Amount matches payment
- userId is valid
- Timestamp makes sense
```

#### /users/{userId}
```
Verify wallet balance:
- walletBalance increased by payment amount
- lastWalletUpdate timestamp is recent
- No duplicate increases for same payment
```

---

## 🔐 Security Verification

### Before Going Live, Verify:

- [ ] PAYSTACK_SECRET_KEY is secure (not exposed)
- [ ] Only added to `.env` (not in code)
- [ ] Not logged or exposed in error messages
- [ ] Signature verification is working (check logs)
- [ ] Duplicate prevention is working (test with webhook retry)
- [ ] Invalid signatures are rejected (test with wrong key)
- [ ] Error messages don't expose sensitive data
- [ ] Webhook logs don't expose sensitive information

### Test Invalid Webhook
```
To verify signature verification works:

Try sending a fake webhook:
curl -X POST https://datasell.store/api/paystack/webhook \
  -H "Content-Type: application/json" \
  -H "x-paystack-signature: INVALID_SIGNATURE" \
  -d '{"event": "charge.success", "data": {...}}'

Expected: Server logs show ⚠️ Invalid webhook signature
          Request returns 401 Unauthorized
          Wallet NOT credited
```

---

## 📞 What to Do If Issues Persist

### Gather Information
```
1. Screenshot of Paystack webhook settings (URL, status)
2. Recent server logs (last 50 lines)
3. Sample payment reference number (from /payments)
4. User ID that had issue (from /users)
5. Timestamp of payment attempt
6. Any error messages from logs or database
```

### Check Resources
```
1. This guide: COMPLETE_SETUP_GUIDE.md
2. Technical guide: PAYSTACK_WEBHOOK_SETUP.md
3. Architecture: WEBHOOK_ARCHITECTURE.md
4. Code details: CODE_IMPLEMENTATION_DETAILS.md
5. Paystack documentation: https://paystack.com/docs
```

### Contact Support
```
For Paystack issues:
- Email: support@paystack.com
- Help: https://paystack.com/contact

For DataSell webhook issues:
- Check server logs
- Review Firebase database
- Check configuration matches this guide
```

---

## 🎯 Success Criteria

Your webhook is working correctly when:

```
✓ Webhook shows ACTIVE in Paystack dashboard
✓ Payment is made successfully
✓ Wallet is credited within 1 second
✓ Server logs show ✅ messages (not ❌)
✓ SMS notification is received
✓ In-app notification is created
✓ Payment appears in /payments with source: 'webhook'
✓ Webhook event appears in /webhook_logs as 'processed'
✓ User's wallet balance increased correctly
✓ No duplicate credits occur
✓ No errors in server logs
```

If all above are true, your webhook is ✅ WORKING!

---

## 🚀 Going Live Checklist

Once testing is complete:

- [ ] Verify webhook is ACTIVE in Paystack
- [ ] Verify PAYSTACK_SECRET_KEY is production key (sk_live_...)
- [ ] Verify BASE_URL is production domain (https://datasell.store)
- [ ] Verify server is running on production
- [ ] Verify database is production Firebase
- [ ] Test with real payment from real user
- [ ] Monitor first 10 payments for any issues
- [ ] Monitor for 24 hours for patterns
- [ ] Document any issues and solutions
- [ ] Set up monitoring/alerting if desired
- [ ] Celebrate! 🎉 Your webhook is live!

---

## 📈 Performance Benchmarks

Expected performance after setup:

```
Webhook Reception: < 100ms (Paystack → Your Server)
Signature Verification: < 5ms
Database Queries: < 150ms
Wallet Update: < 50ms
Payment Recording: < 50ms
Total Webhook Processing: < 250ms
────────────────────────────────────────────────────
Response to Paystack: < 300ms

User sees wallet update: < 1 second
SMS delivery: 5-30 seconds (async, not blocking)
In-app notification: < 1 second
```

---

## 🎓 Key Takeaways

1. **Webhook URL must be exactly**: `https://datasell.store/api/paystack/webhook`
2. **Webhook status must be**: ACTIVE (green checkmark)
3. **Event must be enabled**: charge.success
4. **Server must be**: Running, accessible, with valid SSL
5. **Environment variables must be**: Correct (PAYSTACK_SECRET_KEY, etc.)
6. **After payment**: Wallet credits within 1 second + SMS received
7. **If problems**: Check server logs first, then Firebase, then Paystack dashboard

---

## 📚 Documentation Map

```
START HERE
    ↓
    ├─→ WEBHOOK_QUICK_START.md (5-minute setup)
    │
    ├─→ This file (COMPLETE_SETUP_GUIDE.md)
    │
    ├─→ PAYSTACK_WEBHOOK_SETUP.md (detailed reference)
    │
    ├─→ WEBHOOK_ARCHITECTURE.md (visual diagrams)
    │
    └─→ CODE_IMPLEMENTATION_DETAILS.md (code reference)
```

---

**Setup Date**: January 3, 2026
**Last Updated**: January 3, 2026
**Version**: 1.0
**Status**: ✅ Ready for Configuration

Good luck! 🚀
