//! The one sign-in flow every surface drives.
//!
//! Sign-in is disabled in this build: every attempt fails immediately, with
//! no browser page, no local callback server and no token storage. The type
//! stays the single app-wide point so callers keep their existing
//! subscriptions and failure paths.

use gpui::{App, AppContext, Context, Entity, EventEmitter, Global};

use crate::i18n::tr;
use crate::main_window::TargetType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInOrigin {
    Settings,
    Editor,
    ScreenshotEditor,
    Overlay(TargetType),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInOutcome {
    SignedIn,
    Cancelled,
    TimedOut,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInEvent {
    Finished {
        origin: SignInOrigin,
        outcome: SignInOutcome,
    },
    AccountRefreshed,
}

pub struct SignIn;

struct SignInGlobal(Entity<SignIn>);

impl Global for SignInGlobal {}

impl EventEmitter<SignInEvent> for SignIn {}

impl SignIn {
    pub fn init(cx: &mut App) {
        let entity = cx.new(|_| Self);
        cx.set_global(SignInGlobal(entity));
    }

    pub fn global(cx: &App) -> Entity<Self> {
        cx.global::<SignInGlobal>().0.clone()
    }

    pub fn is_pending(&self) -> bool {
        false
    }

    pub fn pending_origin(&self) -> Option<SignInOrigin> {
        None
    }

    /// Disabled in this build: report failure without opening a browser,
    /// starting the local callback server or storing any token.
    pub fn start(&mut self, origin: SignInOrigin, cx: &mut Context<Self>) {
        cx.emit(SignInEvent::Finished {
            origin,
            outcome: SignInOutcome::Failed(tr::editor::export::sign_in_required().to_string()),
        });
    }

    pub fn reopen(&mut self, _cx: &mut Context<Self>) {}

    pub fn cancel(&mut self, _cx: &mut Context<Self>) {}
}
