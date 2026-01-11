//! Session-wide mutable state.

use std::collections::HashMap;
use std::time::Duration;

use codex_protocol::models::ResponseItem;

use crate::codex::SessionConfiguration;
use crate::context_manager::ContextManager;
use crate::protocol::RateLimitSnapshot;
use crate::protocol::TokenUsage;
use crate::protocol::TokenUsageInfo;
use crate::truncate::TruncationPolicy;

/// Persistent, session-scoped state previously stored directly on `Session`.
pub(crate) struct SessionState {
    pub(crate) session_configuration: SessionConfiguration,
    pub(crate) history: ContextManager,
    pub(crate) latest_rate_limits: Option<RateLimitSnapshot>,
    pub(crate) latest_api_token_usage: Option<TokenUsage>,
    pub(crate) auto_compact_enabled: bool,
    pub(crate) low_context_warning_state: LowContextWarningState,
    pub(crate) mcp_startup_timeout_overrides: HashMap<String, Duration>,
}

impl SessionState {
    /// Create a new session state mirroring previous `State::default()` semantics.
    pub(crate) fn new(session_configuration: SessionConfiguration) -> Self {
        let history = ContextManager::new();
        Self {
            session_configuration,
            history,
            latest_rate_limits: None,
            latest_api_token_usage: None,
            auto_compact_enabled: false,
            low_context_warning_state: LowContextWarningState::default(),
            mcp_startup_timeout_overrides: HashMap::new(),
        }
    }

    // History helpers
    pub(crate) fn record_items<I>(&mut self, items: I, policy: TruncationPolicy)
    where
        I: IntoIterator,
        I::Item: std::ops::Deref<Target = ResponseItem>,
    {
        self.history.record_items(items, policy);
    }

    pub(crate) fn clone_history(&self) -> ContextManager {
        self.history.clone()
    }

    pub(crate) fn replace_history(&mut self, items: Vec<ResponseItem>) {
        self.history.replace(items);
    }

    pub(crate) fn set_token_info(&mut self, info: Option<TokenUsageInfo>) {
        self.history.set_token_info(info);
    }

    // Token/rate limit helpers
    pub(crate) fn update_token_info_from_usage(
        &mut self,
        usage: &TokenUsage,
        model_context_window: Option<i64>,
        full_model_context_window: Option<i64>,
    ) {
        self.latest_api_token_usage = Some(usage.clone());
        self.history
            .update_token_info(usage, model_context_window, full_model_context_window);
    }

    pub(crate) fn token_info(&self) -> Option<TokenUsageInfo> {
        self.history.token_info()
    }

    pub(crate) fn set_rate_limits(&mut self, snapshot: RateLimitSnapshot) {
        self.latest_rate_limits = Some(merge_rate_limit_fields(
            self.latest_rate_limits.as_ref(),
            snapshot,
        ));
    }

    pub(crate) fn token_info_and_rate_limits(
        &self,
    ) -> (Option<TokenUsageInfo>, Option<RateLimitSnapshot>) {
        (self.token_info(), self.latest_rate_limits.clone())
    }

    pub(crate) fn set_token_usage_full(
        &mut self,
        context_window: i64,
        full_model_context_window: Option<i64>,
    ) {
        self.latest_api_token_usage = Some(TokenUsage {
            total_tokens: context_window,
            ..TokenUsage::default()
        });
        self.history
            .set_token_usage_full(context_window, full_model_context_window);
    }

    pub(crate) fn auto_compact_enabled(&self) -> bool {
        self.auto_compact_enabled
    }

    pub(crate) fn set_auto_compact_enabled(&mut self, enabled: bool) {
        self.auto_compact_enabled = enabled;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LowContextWarningState {
    pub(crate) warned_autocompact_threshold: bool,
    pub(crate) warned_manual_compact: bool,
}

impl LowContextWarningState {
    pub(crate) fn reset_if_recovered(&mut self, percent_remaining: i64) {
        if percent_remaining > 20 {
            *self = Self::default();
        }
    }
}

// Sometimes new snapshots don't include credits or plan information.
fn merge_rate_limit_fields(
    previous: Option<&RateLimitSnapshot>,
    mut snapshot: RateLimitSnapshot,
) -> RateLimitSnapshot {
    if snapshot.credits.is_none() {
        snapshot.credits = previous.and_then(|prior| prior.credits.clone());
    }
    if snapshot.plan_type.is_none() {
        snapshot.plan_type = previous.and_then(|prior| prior.plan_type);
    }
    snapshot
}
