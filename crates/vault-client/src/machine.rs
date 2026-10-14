//! The step interface every procedure shares: requests, prompts, and saves out; responses and
//! answers in; and a final [`Finished`] carrying the state to commit.
//!
//! A procedure is written as straight-line code that awaits each exchange with the caller, and
//! [`Machine`] runs it one exchange at a time by polling it with a no-op waker. No executor or
//! async runtime is involved: the caller sees only [`Machine::start`] and [`Machine::step`].

use crate::error::ClientError;
use crate::state::ClientState;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use vault_core::clock::{BUILD_TIME_MS, check_clock};
use vault_core::rng::Rng;
use vault_core::secret::{SecretKey, SecretString, VaultKey};

/// A request to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `GET /v1/vault`.
    GetVault,
    /// `PUT /v1/vault` with a precondition and the vault file as the body.
    PutVault {
        /// The precondition header.
        condition: Precondition,
        /// The vault file.
        file: Vec<u8>,
    },
    /// `GET /v1/revisions`.
    ListRevisions,
    /// `GET /v1/revisions/<id>`.
    GetRevision(u64),
}

/// The precondition of a `PUT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// `If-Match` with this `ETag`, quoted.
    IfMatch(String),
    /// `If-None-Match: *`.
    IfNoneMatch,
}

/// A server response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
    /// The `Date` header in ms, when present.
    pub date: Option<u64>,
}

/// Why a procedure asks for the master password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// To open the local vault file.
    Unlock,
    /// The remote carries a `wrap_nonce` another device created.
    CredentialsChanged,
    /// To find out whether a `--new-secret-key` push landed.
    PendingSecretKey,
    /// To open a revision during `--recover` that carries an unknown `wrap_nonce`.
    Recovery,
    /// To open a revision for a restore.
    Revision,
}

/// A confirmation the user gives or declines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// The old credentials are not available: discard the unpushed local changes and take the
    /// remote under the new credentials.
    DiscardLocalChanges,
    /// No revision under an unknown `wrap_nonce` opened: confirm that no credential change was
    /// made, so recovery treats those revisions as garbage.
    NoCredentialChange,
}

impl Confirmation {
    /// A description to show with the question.
    pub fn description(self) -> &'static str {
        match self {
            Confirmation::DiscardLocalChanges => {
                "The local changes not yet pushed were made under the old credentials, which \
                 were not given. Discard them and continue with the server's vault?"
            }
            Confirmation::NoCredentialChange => {
                "The server holds revisions under credentials that none of the given ones open. \
                 Confirm that no credential change was made on another device; those revisions \
                 are then treated as damaged."
            }
        }
    }
}

/// A question for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// The master password; answered with [`Answer::Password`]. `failed` counts the earlier wrong
    /// answers to the same question.
    MasterPassword {
        /// Why it is needed.
        purpose: Purpose,
        /// Earlier wrong answers.
        failed: u32,
    },
    /// The master password and a new secret key, after the stored secret key failed; answered
    /// with [`Answer::PasswordAndSecretKey`].
    MasterPasswordAndSecretKey {
        /// Why it is needed.
        purpose: Purpose,
    },
    /// The master password from before another device's credential change, to open unpushed
    /// local changes; answered with [`Answer::Password`] or [`Answer::Declined`].
    OldMasterPassword {
        /// Earlier wrong answers.
        failed: u32,
    },
    /// A new master password to set; answered with [`Answer::Password`]. `rejected` is the rule
    /// the previous answer broke.
    NewMasterPassword {
        /// The rule the previous answer broke.
        rejected: Option<vault_core::Error>,
    },
    /// The secret key, decoded by the caller from its text form; answered with
    /// [`Answer::SecretKey`].
    SecretKey,
    /// The vault ID from the emergency kit, which may be left empty; answered with
    /// [`Answer::VaultId`].
    KitVaultId,
    /// A yes or no question; answered with [`Answer::Confirmed`].
    Confirm(Confirmation),
}

/// An answer to a [`Prompt`].
pub enum Answer {
    /// A master password.
    Password(SecretString),
    /// A master password and a secret key.
    PasswordAndSecretKey(SecretString, SecretKey),
    /// A secret key.
    SecretKey(SecretKey),
    /// The kit's vault ID, or `None` when left empty.
    VaultId(Option<[u8; 16]>),
    /// Yes or no.
    Confirmed(bool),
    /// The user cannot or will not answer.
    Declined,
}

/// The secret key that goes with a [`Save`].
pub enum SavedKey {
    /// Store as the current secret key (`vault init`).
    Current(SecretKey),
    /// Store as the pending secret key (`vault passwd --new-secret-key`).
    Pending(SecretKey),
}

impl SavedKey {
    /// The key.
    pub fn key(&self) -> &SecretKey {
        match self {
            SavedKey::Current(k) | SavedKey::Pending(k) => k,
        }
    }
}

/// A state the caller saves before the procedure pushes, answered with [`Input::Saved`].
///
/// The caller stores the secret key, commits `state` with [`Save::commit`] (for `vault init`,
/// which has no earlier state, it writes `state` as it is), shows the new emergency kit (the
/// secret key and `state.vault_id`), and confirms that the user kept it. From then on `state` is
/// the state this run started from, for the final commit. A caller that cannot save drops the
/// machine. When `vault init` then ends with [`ClientError::UndoSave`], the caller deletes the
/// saved state and secret key again.
pub struct Save {
    /// The state to commit.
    pub state: ClientState,
    /// The secret key to store.
    pub secret_key: SavedKey,
    /// The vault key that opens `state.file`.
    pub vault_key: VaultKey,
}

/// What the caller feeds back.
pub enum Input {
    /// The response to a [`Request`].
    Response(Response),
    /// The [`Request`] failed in transport or timed out.
    Unreachable,
    /// The answer to a [`Prompt`].
    Answer(Answer),
    /// The [`Save`] is done.
    Saved,
}

/// What a procedure needs next, or its end.
pub enum Step<T> {
    /// Send this request and feed back [`Input::Response`] or [`Input::Unreachable`].
    Request(Request),
    /// Ask the user and feed back [`Input::Answer`].
    Prompt(Prompt),
    /// Save and feed back [`Input::Saved`].
    Save(Save),
    /// The procedure ended.
    Done(Finished<T>),
}

/// A change to the stored secret keys that goes with a commit.
pub enum SecretKeyChange {
    /// Store this key as the current one; it replaces the old one.
    Replace(SecretKey),
    /// The pending key replaces the current one.
    PromotePending,
    /// Discard the pending key; the newly printed emergency kit is void.
    DiscardPending,
    /// Store this key as the current one and discard the pending key: another device's change of
    /// secret key was taken over while a `--new-secret-key` push of this device did not land.
    ReplaceAndDiscardPending(SecretKey),
}

/// The end of a procedure.
///
/// The caller commits `state` with [`Finished::commit`] under its lock, applies
/// `secret_key` to its secret stores in the same step, and may cache `vault_key`. Nothing else
/// the procedure did needs storing.
pub struct Finished<T> {
    /// The result.
    pub result: Result<T, ClientError>,
    /// The state to commit, or `None` when nothing changed. A failure can carry a state too, for
    /// example one that records `stopped`.
    pub state: Option<ClientState>,
    /// The vault key that opens the committed state's file, when known.
    pub vault_key: Option<VaultKey>,
    /// The vault key that opens the file the run started from, when known. It differs from
    /// `vault_key` after a credential change.
    pub started_vault_key: Option<VaultKey>,
    /// A change to the stored secret keys.
    pub secret_key: Option<SecretKeyChange>,
}

impl<T> Finished<T> {
    pub(crate) fn error(e: ClientError) -> Finished<T> {
        Finished {
            result: Err(e),
            state: None,
            vault_key: None,
            started_vault_key: None,
            secret_key: None,
        }
    }
}

/// What a procedure hands the caller between inputs.
pub(crate) enum Event {
    Request(Request),
    Prompt(Prompt),
    Save(Box<Save>),
}

#[derive(Default)]
struct Exchange {
    now: u64,
    input: Option<Input>,
    output: Option<Event>,
}

/// The procedure's end of the exchange.
#[derive(Clone, Default)]
pub(crate) struct Io(Arc<Mutex<Exchange>>);

impl Io {
    fn with<R>(&self, f: impl FnOnce(&mut Exchange) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    async fn exchange(&self, event: Event) -> Input {
        self.with(|x| x.output = Some(event));
        NextInput(self).await
    }
}

/// Pending until the caller feeds the next input.
struct NextInput<'a>(&'a Io);

impl Future for NextInput<'_> {
    type Output = Input;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Input> {
        match self.0.with(|x| x.input.take()) {
            Some(i) => Poll::Ready(i),
            None => Poll::Pending,
        }
    }
}

/// What a procedure runs with: the exchange, the caller's random number generator, and the `Date`
/// of the server's most recent response.
pub(crate) struct Cx {
    io: Io,
    rng: Box<dyn Rng + Send>,
    date: Option<u64>,
}

impl Cx {
    /// The caller's clock at this step, in ms.
    pub(crate) fn now(&self) -> u64 {
        self.io.with(|x| x.now)
    }

    pub(crate) fn rng(&mut self) -> &mut dyn Rng {
        &mut *self.rng
    }

    /// The clock check before an edit, a merge, or a push: against the build time, and against
    /// the `Date` of the server's most recent response that carried one.
    pub(crate) fn check_clock(&self) -> Result<(), ClientError> {
        Ok(check_clock(self.now(), BUILD_TIME_MS, self.date)?)
    }

    pub(crate) async fn request(&mut self, r: Request) -> Result<Response, ClientError> {
        match self.io.exchange(Event::Request(r)).await {
            Input::Response(resp) => {
                if resp.date.is_some() {
                    self.date = resp.date;
                }
                Ok(resp)
            }
            Input::Unreachable => Err(ClientError::Unreachable),
            _ => Err(ClientError::UnexpectedInput),
        }
    }

    pub(crate) async fn prompt(&mut self, p: Prompt) -> Result<Answer, ClientError> {
        match self.io.exchange(Event::Prompt(p)).await {
            Input::Answer(a) => Ok(a),
            _ => Err(ClientError::UnexpectedInput),
        }
    }

    pub(crate) async fn password(&mut self, p: Prompt) -> Result<SecretString, ClientError> {
        match self.prompt(p).await? {
            Answer::Password(pw) => Ok(pw),
            Answer::Declined => Err(ClientError::Cancelled),
            _ => Err(ClientError::UnexpectedInput),
        }
    }

    pub(crate) async fn confirm(&mut self, c: Confirmation) -> Result<bool, ClientError> {
        match self.prompt(Prompt::Confirm(c)).await? {
            Answer::Confirmed(yes) => Ok(yes),
            Answer::Declined => Ok(false),
            _ => Err(ClientError::UnexpectedInput),
        }
    }

    pub(crate) async fn save(&mut self, s: Save) -> Result<(), ClientError> {
        match self.io.exchange(Event::Save(Box::new(s))).await {
            Input::Saved => Ok(()),
            _ => Err(ClientError::UnexpectedInput),
        }
    }
}

type Procedure<T> = Pin<Box<dyn Future<Output = Finished<T>> + Send>>;

/// A running procedure. Call [`Machine::start`] once, then [`Machine::step`] with the input for
/// each [`Step`] until [`Step::Done`]. `now` is the caller's clock in ms at each call.
///
/// A caller may drop a machine at any step. Nothing the machine did is stored except what the
/// caller committed from a [`Save`] or a [`Finished`].
pub struct Machine<T> {
    io: Io,
    procedure: Option<Procedure<T>>,
}

impl<T: 'static> Machine<T> {
    pub(crate) fn new<F, Fut>(rng: impl Rng + Send + 'static, f: F) -> Machine<T>
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = Finished<T>> + Send + 'static,
    {
        let io = Io::default();
        let cx = Cx {
            io: io.clone(),
            rng: Box::new(rng),
            date: None,
        };
        Machine {
            io,
            procedure: Some(Box::pin(f(cx))),
        }
    }

    /// Runs the procedure up to its first exchange.
    pub fn start(&mut self, now: u64) -> Step<T> {
        self.resume(None, now)
    }

    /// Feeds the input for the previous step and runs up to the next exchange.
    pub fn step(&mut self, input: Input, now: u64) -> Step<T> {
        self.resume(Some(input), now)
    }

    fn resume(&mut self, input: Option<Input>, now: u64) -> Step<T> {
        let Some(procedure) = self.procedure.as_mut() else {
            return Step::Done(Finished::error(ClientError::UnexpectedInput));
        };
        self.io.with(|x| {
            x.now = now;
            x.input = input;
        });
        match procedure
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(finished) => {
                self.procedure = None;
                Step::Done(finished)
            }
            Poll::Pending => match self.io.with(|x| x.output.take()) {
                Some(Event::Request(r)) => Step::Request(r),
                Some(Event::Prompt(p)) => Step::Prompt(p),
                Some(Event::Save(s)) => Step::Save(*s),
                // Only an exchange suspends a procedure, so an output is always present.
                None => {
                    self.procedure = None;
                    Step::Done(Finished::error(ClientError::UnexpectedInput))
                }
            },
        }
    }
}

impl<T> Finished<T> {
    /// The same end with its result mapped by `f`.
    pub fn map<R>(self, f: impl FnOnce(T) -> R) -> Finished<R> {
        Finished {
            result: self.result.map(f),
            state: self.state,
            vault_key: self.vault_key,
            started_vault_key: self.started_vault_key,
            secret_key: self.secret_key,
        }
    }
}

impl<T> Step<T> {
    /// The same step, with the result of a [`Step::Done`] mapped by `f`.
    pub fn map<R>(self, f: impl FnOnce(T) -> R) -> Step<R> {
        match self {
            Step::Request(r) => Step::Request(r),
            Step::Prompt(p) => Step::Prompt(p),
            Step::Save(s) => Step::Save(s),
            Step::Done(d) => Step::Done(d.map(f)),
        }
    }
}

/// The two calls a running machine answers, whatever its result type.
trait Erased<R>: Send {
    fn start(&mut self, now: u64) -> Step<R>;
    fn step(&mut self, input: Input, now: u64) -> Step<R>;
}

struct Mapped<T, R> {
    machine: Machine<T>,
    map: fn(T) -> R,
}

impl<T: 'static, R> Erased<R> for Mapped<T, R> {
    fn start(&mut self, now: u64) -> Step<R> {
        self.machine.start(now).map(self.map)
    }

    fn step(&mut self, input: Input, now: u64) -> Step<R> {
        self.machine.step(input, now).map(self.map)
    }
}

/// A machine whose result is mapped into one type `R`, so a binding can hold any procedure
/// behind one type. It steps like [`Machine`].
pub struct AnyMachine<R> {
    inner: Box<dyn Erased<R>>,
}

impl<R: 'static> AnyMachine<R> {
    /// Wraps `machine`, mapping its result with `map`.
    pub fn new<T: 'static>(machine: Machine<T>, map: fn(T) -> R) -> AnyMachine<R> {
        AnyMachine {
            inner: Box::new(Mapped { machine, map }),
        }
    }

    /// Runs the procedure up to its first exchange.
    pub fn start(&mut self, now: u64) -> Step<R> {
        self.inner.start(now)
    }

    /// Feeds the input for the previous step and runs up to the next exchange.
    pub fn step(&mut self, input: Input, now: u64) -> Step<R> {
        self.inner.step(input, now)
    }
}
