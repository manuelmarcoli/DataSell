# Quick Webhook Configuration Guide

## ⚡ Quick Start (5 minutes)

### Step 1: Go to Paystack Dashboard
Visit: https://dashboard.paystack.com → Settings → API Keys & Webhooks

### Step 2: Add Webhook URL
```
https://datasell.store/api/paystack/webhook
```

### Step 3: Enable charge.success Event
Check the `charge.success` checkbox

### Step 4: Save
Click "Save" and confirm webhook is **Active** ✓

## ✅ Verify It's Working

### Test 1: Make a Payment
1. Go to DataSell app
2. Add funds to wallet
3. Complete payment on Paystack

### Expected Results:
- ✅ User wallet credited immediately
- ✅ SMS notification sent to user
- ✅ In-app notification created
- ✅ Server logs show: "✅ Wallet credited via webhook"

### Test 2: Check Logs
```
In Server Console, you should see:
🔔 Webhook event received: charge.success
✅ Wallet credited via webhook: [userId] received ₵[amount]
✅ Webhook processed successfully
```

## 🔒 Security Verification

The webhook endpoint automatically:
- ✅ Verifies Paystack signature
- ✅ Prevents duplicate payments
- ✅ Validates user exists
- ✅ Records all transactions

## 📊 Payment Flow

```
Payment Initiated
    ↓
User Completes Payment
    ↓
Paystack Confirms
    ↓
[AUTOMATIC] Webhook Sent to Server
    ↓
[AUTOMATIC] Wallet Credited
    ↓
[AUTOMATIC] SMS Sent
    ↓
Transaction Complete ✓
```

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| Webhook not called | Verify URL in dashboard matches exactly |
| Signature error | Check PAYSTACK_SECRET_KEY in .env |
| Wallet not credited | Check server logs for errors |
| SMS not sent | Verify MNOTIFY_API_KEY in .env |

## 📝 Environment Requirements

Ensure these are in your `.env`:
```
PAYSTACK_SECRET_KEY=sk_live_...
PAYSTACK_PUBLIC_KEY=pk_live_...
PAYSTACK_BASE_URL=https://api.paystack.co
BASE_URL=https://datasell.store
```

## 🎯 What Happens When Payment is Confirmed

The webhook automatically:

1. **Verifies it's from Paystack** (signature check)
2. **Checks for duplicates** (prevents double-crediting)
3. **Credits the wallet** (adds amount to user's balance)
4. **Records the payment** (stores in database)
5. **Sends SMS** (notifies user via text)
6. **Creates notification** (in-app alert)
7. **Logs everything** (audit trail for support)

## 🚀 That's It!

Once the webhook URL is configured in Paystack, all future payments will be:
- ✅ Automatically confirmed
- ✅ Instantly credited
- ✅ Notification sent to user
- ✅ Recorded in system

No manual intervention needed!

---

**For detailed setup and troubleshooting**, see: `PAYSTACK_WEBHOOK_SETUP.md`
