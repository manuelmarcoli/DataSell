# Paystack Webhook Setup Guide

## Overview
This document explains how to configure Paystack to automatically credit user accounts when payments are confirmed. The webhook system sends real-time payment notifications from Paystack to your DataSell server, enabling instant account crediting without requiring users to wait or manually verify.

## Features
✅ Automatic wallet crediting after successful payment
✅ SMS notifications to users
✅ In-app notifications
✅ Duplicate payment prevention
✅ Webhook signature verification (secure)
✅ Comprehensive logging
✅ Error handling and recovery

## Webhook Endpoint Details

### URL
```
https://datasell.store/api/paystack/webhook
```

### Method
```
POST
```

### Events Processed
- `charge.success` - When a payment is successfully completed

### Payment Status
- Only processes payments with status: `success`

## Step-by-Step Setup Instructions

### 1. Log in to Paystack Dashboard
1. Go to [https://dashboard.paystack.com](https://dashboard.paystack.com)
2. Sign in with your credentials
3. Navigate to **Settings** → **API Keys & Webhooks**

### 2. Configure Webhook URL
1. Look for the "Webhooks" section
2. Click on "Add a webhook" or edit existing webhook
3. Enter the webhook URL:
   ```
   https://datasell.store/api/paystack/webhook
   ```

### 3. Select Events to Subscribe
Make sure to enable/check the following event:
- ✓ `charge.success` (Payment Successful)

You can also enable these for monitoring:
- `charge.failed` (optional)
- `charge.dispute.create` (optional)
- `charge.dispute.resolve` (optional)
- `transfer.success` (optional)

### 4. Verify Webhook is Active
1. Save the webhook configuration
2. You should see a "✓ Active" status next to your webhook URL
3. Paystack will send you a test webhook - check your server logs for confirmation

## How It Works

### Payment Flow
```
1. User initiates payment through DataSell
   ↓
2. DataSell sends payment initialization to Paystack
   ↓
3. User completes payment on Paystack payment page
   ↓
4. Paystack confirms payment success
   ↓
5. **Paystack sends webhook to: /api/paystack/webhook**
   ↓
6. DataSell verifies webhook signature
   ↓
7. DataSell credits user's wallet
   ↓
8. SMS notification sent to user
   ↓
9. In-app notification created
```

### Webhook Processing Steps

#### 1. Signature Verification
The webhook endpoint verifies that the request is genuinely from Paystack by:
- Extracting the `x-paystack-signature` header
- Computing HMAC-SHA512 hash of the request body using your `PAYSTACK_SECRET_KEY`
- Comparing the computed hash with the signature from Paystack
- Rejecting unsigned or fraudulent requests

#### 2. Duplicate Prevention
Before crediting the wallet:
- Checks if a payment with this reference already exists
- If duplicate found, acknowledges the webhook but doesn't credit again
- This prevents accidental double-crediting from webhook retries

#### 3. Wallet Crediting
- Retrieves the original amount from payment metadata
- Gets current user wallet balance from Firebase
- Updates wallet with new balance
- Records timestamp of update

#### 4. Payment Recording
Creates a payment record in Firebase with:
- User ID
- Amount credited
- Paystack amount (with fees)
- Transaction reference
- Payment source (webhook)
- Full Paystack data
- Timestamp

#### 5. User Notifications
- **SMS**: Sends SMS to user's phone notifying them of credit
- **In-App**: Creates notification in the app's notification system

## Webhook Payload Example

```json
{
  "event": "charge.success",
  "data": {
    "id": 123456789,
    "authorization": {
      "authorization_code": "AUTH_72btv...",
      "bin": "539999",
      "last4": "8381",
      "exp_month": "12",
      "exp_year": "2025",
      "channel": "card",
      "card_type": "visa",
      "bank": null,
      "country_code": "NG",
      "brand": "Visa",
      "reusable": true,
      "signature": "SIG_xQQZ1iVFXK1m0jhQZS..."
    },
    "reference": "77z1h11h4q",
    "amount": 50000,
    "paid_at": "2025-01-03T12:34:56.000Z",
    "created_at": "2025-01-03T12:30:00.000Z",
    "channel": "card",
    "currency": "GHS",
    "ip_address": "192.168.1.1",
    "metadata": {
      "userId": "user123abc",
      "purpose": "wallet_funding",
      "originalAmount": 500
    },
    "log": null,
    "fees": null,
    "fees_split": null,
    "customer": {
      "id": 987654321,
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com",
      "phone": "+2341234567890",
      "customer_code": "CUS_xxxx",
      "risk_action": "default"
    },
    "status": "success"
  }
}
```

## Testing the Webhook

### Method 1: Paystack Test Mode
1. Use Paystack test card details to make a payment
2. Complete the payment flow
3. Check your server logs for the webhook processing message

### Method 2: Manual Testing with curl
```bash
# Test webhook endpoint
curl -X POST https://datasell.store/api/paystack/webhook \
  -H "Content-Type: application/json" \
  -H "x-paystack-signature: YOUR_COMPUTED_SIGNATURE" \
  -d '{
    "event": "charge.success",
    "data": {
      "reference": "test123",
      "amount": 50000,
      "status": "success",
      "metadata": {
        "userId": "test-user-id",
        "originalAmount": 500
      }
    }
  }'
```

## Monitoring & Logging

### Server Logs
Check your server logs for webhook processing messages:
```
🔔 Webhook event received: charge.success
📋 Webhook data: { ... }
✅ Wallet credited via webhook: user123 received ₵500
✅ Webhook processed successfully for reference: 77z1h11h4q
```

### Error Logs
If something goes wrong:
```
⚠️ Invalid webhook signature from Paystack
❌ User not found: invalid-user-id
❌ Webhook processing error: ...
```

### Firebase Database
- **Payments Records**: `/payments` - All payment transactions
- **Webhook Logs**: `/webhook_logs` - All webhook events processed
- **User Wallet**: `/users/{userId}/walletBalance` - Current wallet balance
- **Notifications**: `/notifications` - In-app notifications sent

## Troubleshooting

### Issue: Webhook not being called
**Solution:**
1. Verify webhook URL is correctly configured in Paystack dashboard
2. Check that `charge.success` event is enabled
3. Ensure your server is accessible from the internet (not on localhost)
4. Verify SSL certificate is valid (HTTPS required)

### Issue: Signature verification failing
**Solution:**
1. Verify `PAYSTACK_SECRET_KEY` in `.env` matches your Paystack account
2. Check that the key is the **secret key**, not public key
3. Ensure there are no extra spaces or characters in the key

### Issue: User wallet not being credited
**Solution:**
1. Check server logs for error messages
2. Verify user ID in payment metadata is correct
3. Ensure user exists in Firebase database
4. Check Firebase database permissions

### Issue: Duplicate payments
**Solution:**
- The system has built-in duplicate prevention
- If you see "Payment already processed" messages, this is normal
- Paystack may retry the webhook, but DataSell will reject duplicates

### Issue: SMS not being sent
**Solution:**
1. Verify `MNOTIFY_API_KEY` is configured in `.env`
2. Check that user phone number is stored correctly
3. Review SMS logs in server console

## Security Considerations

### ✅ Implemented Security Measures
1. **Signature Verification**: Every webhook is verified using HMAC-SHA512
2. **Secret Key Protection**: Stored securely in `.env` file
3. **Duplicate Prevention**: Prevents accidental double-crediting
4. **User Validation**: Ensures user exists before crediting
5. **Logging**: All webhooks are logged for audit trail

### ⚠️ Best Practices
1. Keep `PAYSTACK_SECRET_KEY` secure and never expose it
2. Regularly review webhook logs for suspicious activity
3. Monitor wallet balance changes for unusual patterns
4. Implement rate limiting if needed (can add middleware)

## API Endpoints Reference

### Initialize Payment (User-triggered)
```
POST /api/initialize-payment
Requires: Authentication
Body: { amount: number }
```

### Verify Payment (Client-side verification, optional)
```
GET /api/verify-payment/:reference
Requires: Authentication
Returns: Payment verification status
```

### Webhook (Server-to-server, automatic)
```
POST /api/paystack/webhook
Headers: x-paystack-signature: signature
Body: Paystack webhook payload
No authentication required (signature verified instead)
```

## Configuration Checklist

- [ ] Paystack account created and verified
- [ ] Webhook URL added to Paystack dashboard: `https://datasell.store/api/paystack/webhook`
- [ ] Event `charge.success` is enabled
- [ ] `PAYSTACK_SECRET_KEY` is correctly set in `.env`
- [ ] Server is running and accessible from the internet
- [ ] SSL/HTTPS certificate is valid
- [ ] Test payment completed successfully
- [ ] Wallet was credited automatically
- [ ] SMS notification was received
- [ ] Server logs show successful webhook processing

## Additional Notes

### Metadata Structure
The metadata sent with the payment initialization is crucial:
```json
{
  "userId": "firebase-user-id",
  "purpose": "wallet_funding",
  "originalAmount": 500
}
```

### Amount Handling
- Paystack stores amounts in **smallest currency unit** (e.g., 50000 = 500.00)
- The system accounts for this conversion automatically
- Original amount is preserved in metadata for accurate crediting

### Session vs. Webhook
- **Client verification** (`/api/verify-payment`): Used when user returns from Paystack
- **Webhook**: Used when Paystack sends automatic notification
- Both methods result in wallet crediting
- Duplicate prevention ensures user isn't credited twice

## Support

For issues with:
- **Paystack Setup**: Contact Paystack support at support@paystack.com
- **DataSell Integration**: Check server logs and webhook logs in Firebase
- **Payment Not Processed**: Review payment records in Firebase `/payments` node

---

**Last Updated**: January 3, 2026
**Status**: ✅ Ready for Production
