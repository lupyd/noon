use deadpool_postgres::Pool;
use deadpool_postgres::tokio_postgres::types::Type;
use std::time::SystemTime;

pub struct SubscriptionInfo {
    pub owner: String,
    pub tier: String,
    pub razorpay_subscription_id: Option<String>,
    pub razorpay_plan_id: Option<String>,
    pub subscription_status: String,
    /// Unix timestamp seconds of billing period end, None if free/inactive
    pub current_period_end: Option<i64>,
}

/// Returns subscription info for owner, or free-tier defaults if no record exists.
pub async fn get_subscription_info(pool: &Pool, owner: &str) -> anyhow::Result<SubscriptionInfo> {
    let client = pool.get().await?;
    let rows = client
        .query_typed(
            "SELECT tier, razorpay_subscription_id, razorpay_plan_id, subscription_status, \
             extract(epoch from current_period_end)::bigint \
             FROM user_subscriptions WHERE owner = $1",
            &[(&owner, Type::VARCHAR)],
        )
        .await?;

    if let Some(row) = rows.into_iter().next() {
        Ok(SubscriptionInfo {
            owner: owner.to_string(),
            tier: row.get(0),
            razorpay_subscription_id: row.get(1),
            razorpay_plan_id: row.get(2),
            subscription_status: row.get(3),
            current_period_end: row.get(4),
        })
    } else {
        Ok(SubscriptionInfo {
            owner: owner.to_string(),
            tier: "free".to_string(),
            razorpay_subscription_id: None,
            razorpay_plan_id: None,
            subscription_status: "inactive".to_string(),
            current_period_end: None,
        })
    }
}

/// Store a newly-created Razorpay subscription as "pending" until the webhook activates it.
pub async fn upsert_pending_subscription(
    pool: &Pool,
    owner: &str,
    razorpay_subscription_id: &str,
    razorpay_plan_id: &str,
    tier: &str,
) -> anyhow::Result<()> {
    let client = pool.get().await?;
    client
        .query_typed(
            "INSERT INTO user_subscriptions \
                 (owner, tier, razorpay_subscription_id, razorpay_plan_id, subscription_status, updated_at) \
             VALUES ($1, $2, $3, $4, 'pending', NOW()) \
             ON CONFLICT (owner) DO UPDATE SET \
                 tier                     = EXCLUDED.tier, \
                 razorpay_subscription_id = EXCLUDED.razorpay_subscription_id, \
                 razorpay_plan_id         = EXCLUDED.razorpay_plan_id, \
                 subscription_status      = 'pending', \
                 updated_at               = NOW()",
            &[
                (&owner, Type::VARCHAR),
                (&tier, Type::VARCHAR),
                (&razorpay_subscription_id, Type::VARCHAR),
                (&razorpay_plan_id, Type::VARCHAR),
            ],
        )
        .await?;
    Ok(())
}

/// Activate or refresh a subscription triggered by a webhook event.
pub async fn activate_subscription(
    pool: &Pool,
    razorpay_subscription_id: &str,
    status: &str,
    current_period_end_unix: Option<i64>,
) -> anyhow::Result<()> {
    let client = pool.get().await?;
    let period_end: Option<SystemTime> = current_period_end_unix
        .map(|ts| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(ts as u64));

    client
        .query_typed(
            "UPDATE user_subscriptions \
             SET subscription_status = $2, current_period_end = $3, updated_at = NOW() \
             WHERE razorpay_subscription_id = $1",
            &[
                (&razorpay_subscription_id, Type::VARCHAR),
                (&status, Type::VARCHAR),
                (&period_end, Type::TIMESTAMPTZ),
            ],
        )
        .await?;
    Ok(())
}

/// Downgrade to free tier on cancellation / halt / completion.
pub async fn cancel_subscription(
    pool: &Pool,
    razorpay_subscription_id: &str,
    status: &str,
) -> anyhow::Result<()> {
    let client = pool.get().await?;
    client
        .query_typed(
            "UPDATE user_subscriptions \
             SET tier = 'free', subscription_status = $2, current_period_end = NULL, updated_at = NOW() \
             WHERE razorpay_subscription_id = $1",
            &[
                (&razorpay_subscription_id, Type::VARCHAR),
                (&status, Type::VARCHAR),
            ],
        )
        .await?;
    Ok(())
}
