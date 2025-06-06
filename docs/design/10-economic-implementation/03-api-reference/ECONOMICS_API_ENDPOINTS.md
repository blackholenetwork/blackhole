# Economics API Endpoints Reference

This document outlines all HTTP API endpoints related to the economic system based on the actual implementation.

## Base URL Structure

All economic endpoints are prefixed with `/api/v1/economics/`

## Authentication

All endpoints require authentication via JWT token or session-based auth:
```
Authorization: Bearer <jwt_token>
```

## Dashboard Endpoints

### GET `/api/v1/economics/dashboard`
Get user-specific economic dashboard data.

**Response varies by user type:**

#### Subscriber Dashboard
```json
{
  "user_type": "subscriber",
  "subscription": {
    "tier": "normal",
    "price": 10.00,
    "status": "active",
    "renewal_date": "2024-01-15T00:00:00Z"
  },
  "revenue_distribution": {
    "content_creators": 7.00,
    "infrastructure": 2.50,
    "network_ops": 0.25,
    "app_developers": 0.25
  },
  "usage_stats": {
    "storage_gb": 15.2,
    "bandwidth_gb": 45.8,
    "compute_hours": 12.5
  }
}
```

#### Content Creator Dashboard
```json
{
  "user_type": "content_creator",
  "earnings": {
    "current_month": 247.50,
    "last_month": 189.25,
    "total_lifetime": 1847.80
  },
  "content_performance": {
    "total_views": 15420,
    "engagement_rate": 0.68,
    "top_content": [
      {
        "content_id": "content_123",
        "title": "Tutorial Video",
        "revenue": 45.20,
        "views": 2340
      }
    ]
  },
  "investment_stats": {
    "total_investors": 23,
    "investor_share": 74.25,
    "creator_share": 173.25
  }
}
```

#### Infrastructure Provider Dashboard
```json
{
  "user_type": "infrastructure_provider",
  "provider_stats": {
    "total_earnings": 156.78,
    "efficiency_rating": 0.94,
    "resource_utilization": {
      "storage": 0.87,
      "bandwidth": 0.92,
      "compute": 0.76
    }
  },
  "market_position": {
    "storage_rank": 15,
    "bandwidth_rank": 8,
    "compute_rank": 22
  },
  "rewards": {
    "base_rewards": 130.65,
    "efficiency_bonus": 26.13
  }
}
```

### WebSocket `/api/v1/economics/dashboard/stream`
Real-time dashboard updates via WebSocket.

**Connection**: Upgrade to WebSocket with auth headers
**Messages**: JSON objects with real-time economic updates

```json
{
  "type": "revenue_update",
  "timestamp": "2024-01-10T15:30:45Z",
  "data": {
    "user_id": "user_123",
    "amount": 0.0028,
    "resource_type": "content",
    "description": "Content view reward"
  }
}
```

## Subscription Management Endpoints

### GET `/api/v1/economics/subscription`
Get current user's subscription details.

```json
{
  "id": "sub_abc123",
  "user_id": "user_123",
  "tier": "normal",
  "status": "active",
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-02-01T00:00:00Z",
  "auto_renew": true,
  "price": 10.00,
  "currency": "USD"
}
```

### POST `/api/v1/economics/subscription`
Create or update subscription.

**Request Body:**
```json
{
  "tier": "advance",
  "auto_renew": true,
  "payment_method": "stripe_pm_123"
}
```

### DELETE `/api/v1/economics/subscription`
Cancel subscription.

**Query Parameters:**
- `immediate` (boolean): Cancel immediately vs. end of billing period

## Usage Tracking Endpoints

### GET `/api/v1/economics/usage`
Get usage statistics for the current billing period.

**Query Parameters:**
- `resource_type` (optional): Filter by storage, bandwidth, compute, content
- `start_date` (optional): ISO date string
- `end_date` (optional): ISO date string

```json
{
  "billing_period": "2024-01",
  "usage": [
    {
      "resource_type": "storage",
      "amount": 15.2,
      "unit": "GB",
      "cost": 0.35
    },
    {
      "resource_type": "bandwidth",
      "amount": 45.8,
      "unit": "GB", 
      "cost": 4.12
    }
  ],
  "total_cost": 4.47
}
```

### POST `/api/v1/economics/usage/track`
Record a usage event (internal API for system components).

**Request Body:**
```json
{
  "resource_type": "storage",
  "operation": "put",
  "amount": 0.5,
  "unit": "GB",
  "provider_id": "provider_456",
  "context": {
    "user_initiated": true,
    "chargeable": true
  }
}
```

## Content Economy Endpoints

### GET `/api/v1/economics/content/investments`
Get user's content investments.

```json
{
  "investments": [
    {
      "investment_id": "inv_789",
      "content_id": "content_123",
      "creator_id": "creator_456",
      "investment_amount": 25.00,
      "ownership_percentage": 0.15,
      "current_value": 32.50,
      "total_returns": 7.50
    }
  ],
  "total_invested": 150.00,
  "total_returns": 45.80
}
```

### POST `/api/v1/economics/content/invest`
Invest in content.

**Request Body:**
```json
{
  "content_id": "content_123",
  "investment_amount": 25.00
}
```

### GET `/api/v1/economics/content/creator-stats`
Get content creator performance statistics.

```json
{
  "total_revenue": 1847.80,
  "total_investors": 23,
  "content_count": 15,
  "avg_revenue_per_content": 123.19,
  "top_performing_content": [
    {
      "content_id": "content_123",
      "revenue": 245.60,
      "investor_count": 8,
      "roi": 1.85
    }
  ]
}
```

## Market Data Endpoints

### GET `/api/v1/economics/market/rates`
Get current market rates for resources.

```json
{
  "storage_per_gb_month": 0.023,
  "bandwidth_per_gb": 0.09,
  "compute_per_cpu_hour": 0.0464,
  "memory_per_gb_hour": 0.0058,
  "last_updated": "2024-01-10T12:00:00Z"
}
```

### GET `/api/v1/economics/market/distribution`
Get current revenue distribution percentages.

```json
{
  "content_creator_percentage": 70.0,
  "network_ops_percentage": 2.5,
  "app_developer_percentage": 2.5,
  "infrastructure_percentage": 25.0,
  "effective_date": "2024-01-01T00:00:00Z"
}
```

## Payment Endpoints

### GET `/api/v1/economics/payments/history`
Get payment history.

**Query Parameters:**
- `limit` (default: 50)
- `offset` (default: 0)
- `type`: Filter by 'subscription', 'payout', 'refund'

```json
{
  "payments": [
    {
      "payment_id": "pay_123",
      "type": "subscription",
      "amount": 10.00,
      "currency": "USD",
      "status": "completed",
      "date": "2024-01-01T00:00:00Z",
      "description": "Monthly subscription - Normal tier"
    }
  ],
  "total_count": 15,
  "has_more": true
}
```

### POST `/api/v1/economics/payments/payout`
Request payout (for content creators and providers).

**Request Body:**
```json
{
  "amount": 150.00,
  "payout_method": "bank_transfer",
  "account_details": {
    "account_number": "****1234",
    "routing_number": "021000021"
  }
}
```

## Analytics Endpoints

### GET `/api/v1/economics/analytics/revenue-trend`
Get revenue trend data.

**Query Parameters:**
- `period`: 'daily', 'weekly', 'monthly'
- `start_date`, `end_date`: ISO date strings

```json
{
  "period": "daily",
  "data_points": [
    {
      "date": "2024-01-01",
      "total_revenue": 2450.00,
      "subscription_revenue": 1960.00,
      "content_revenue": 490.00
    }
  ]
}
```

### GET `/api/v1/economics/analytics/user-growth`
Get user growth and economic participation metrics.

```json
{
  "total_subscribers": 1250,
  "total_creators": 89,
  "total_providers": 156,
  "growth_rate": 0.15,
  "churn_rate": 0.03
}
```

## Administrative Endpoints

### GET `/api/v1/economics/admin/system-health`
System health and economic metrics (admin only).

```json
{
  "total_pool_balance": 125000.00,
  "daily_distribution": 8750.00,
  "pending_payouts": 3240.00,
  "system_utilization": 0.87,
  "billing_engine_status": "healthy"
}
```

### POST `/api/v1/economics/admin/adjust-rates`
Adjust market rates (admin only).

**Request Body:**
```json
{
  "storage_per_gb_month": 0.025,
  "bandwidth_per_gb": 0.095,
  "effective_date": "2024-02-01T00:00:00Z"
}
```

## Error Responses

All endpoints follow consistent error response format:

```json
{
  "error": {
    "code": "INSUFFICIENT_BALANCE",
    "message": "Insufficient balance for requested operation",
    "details": {
      "required": 25.00,
      "available": 18.50
    }
  }
}
```

## Rate Limiting

- Standard endpoints: 100 requests/minute
- Dashboard stream: 1 connection per user
- Payment endpoints: 10 requests/minute
- Admin endpoints: 50 requests/minute

## SDK Integration

Economic endpoints are accessible via the official SDK:

```javascript
const client = new BlackholeClient({ apiKey: 'your_api_key' });

// Get dashboard data
const dashboard = await client.economics.getDashboard();

// Subscribe to real-time updates
client.economics.streamDashboard((update) => {
  console.log('Revenue update:', update);
});
```