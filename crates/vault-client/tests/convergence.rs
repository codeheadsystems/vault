//! Two or three clients make random edits and run syncs one exchange at a time, in random
//! interleavings, against one server. Local edits land while syncs are in flight, so the commit
//! rule runs too. Afterwards every client converges on the server's file, no password set on an
//! item that was never deleted is lost, and generations only increase.

mod common;

use common::*;
use proptest::prelude::*;
use std::collections::BTreeMap;
use vault_client::sync::{SyncReport, sync};
use vault_client::{ClientError, ClientState, Input, Machine, Step};
use vault_core::body::Body;
use vault_core::edit::{delete_item, update_item};
use vault_core::file::{open_file, read_header};

#[derive(Debug, Clone)]
enum Action {
    Add,
    SetPassword(usize),
    Delete(usize),
}

#[derive(Debug, Clone)]
enum Op {
    Edit(usize, Action),
    /// Starts a sync, or feeds the in-flight sync its next response.
    Step(usize),
}

fn op(clients: usize) -> impl Strategy<Value = Op> {
    let action = prop_oneof![
        2 => Just(Action::Add),
        4 => (0usize..8).prop_map(Action::SetPassword),
        1 => (0usize..8).prop_map(Action::Delete),
    ];
    prop_oneof![
        1 => (0..clients, action).prop_map(|(c, a)| Op::Edit(c, a)),
        3 => (0..clients).prop_map(Op::Step),
    ]
}

struct InFlight {
    machine: Machine<SyncReport>,
    started: ClientState,
    step: Step<SyncReport>,
    /// Revisions on the server when the sync started.
    revisions: usize,
}

/// `(modified, modified_by)`.
type Stamp = (u64, String);

struct World {
    server: Server,
    clients: Vec<Client>,
    flights: Vec<Option<InFlight>>,
    now: u64,
    /// Every password set on each item, in order.
    passwords: BTreeMap<String, Vec<String>>,
    deleted: Vec<String>,
    /// Each item's stamps, `(modified, modified_by)`, with whether the change was an edit or a
    /// delete.
    stamps: BTreeMap<String, Vec<(Stamp, bool)>>,
    conflicts: usize,
    counter: u64,
    accepted: Vec<u64>,
}

impl World {
    fn new(n: usize) -> World {
        let fx = Fixture::new(0x42);
        let file = fx.file(1, &Body::default(), 1);
        let mut server = Server::default();
        server.store(file.clone(), "laptop");
        let mut state = fx.state(file.clone());
        state.accept(1, file);
        let clients = (0..n)
            .map(|i| {
                let mut c = Client::new(state.clone(), fx.key(), 0x10 + i as u8);
                c.token = TOKEN.into();
                c
            })
            .collect();
        World {
            server,
            clients,
            flights: (0..n).map(|_| None).collect(),
            now: T0,
            passwords: BTreeMap::new(),
            deleted: Vec::new(),
            stamps: BTreeMap::new(),
            conflicts: 0,
            counter: 0,
            accepted: vec![1; n],
        }
    }

    fn tick(&mut self) -> u64 {
        self.now += 1000;
        self.server.date = Some(self.now);
        self.now
    }

    fn live_ids(&self, c: usize) -> Vec<String> {
        let mut ids: Vec<String> = self.clients[c]
            .body()
            .items
            .iter()
            .map(|i| i.id.clone())
            .collect();
        ids.sort();
        ids
    }

    fn edit(&mut self, c: usize, action: Action) {
        let now = self.tick();
        self.counter += 1;
        let n = self.counter;
        let ids = self.live_ids(c);
        let stamp = (now, hex::encode(self.clients[c].device));
        match action {
            Action::Add => {
                let pw = format!("p{n}");
                let mut id = String::new();
                self.clients[c].edit(|b, rng, dev| {
                    id = add_login(b, rng, dev, &format!("item {n}"), &pw, now)
                });
                self.stamps.insert(id.clone(), vec![(stamp, true)]);
                self.passwords.insert(id, vec![pw]);
            }
            Action::SetPassword(slot) if !ids.is_empty() => {
                let id = ids[slot % ids.len()].clone();
                // A login keeps its current password and ten retired ones.
                if self.passwords[&id].len() >= 11 {
                    return;
                }
                let pw = format!("p{n}");
                self.clients[c].edit(|b, _, dev| {
                    let mut f = b.item(&id).unwrap().fields().unwrap().clone();
                    f.login.as_mut().unwrap().password = pw.clone();
                    update_item(b, &id, f, now, dev).unwrap();
                });
                self.passwords.get_mut(&id).unwrap().push(pw);
                self.stamps.get_mut(&id).unwrap().push((stamp, true));
            }
            Action::Delete(slot) if !ids.is_empty() => {
                let id = ids[slot % ids.len()].clone();
                self.clients[c].edit(|b, _, dev| delete_item(b, &id, now, dev).unwrap());
                self.stamps.get_mut(&id).unwrap().push((stamp, false));
                self.deleted.push(id);
            }
            _ => {}
        }
    }

    /// One exchange of client `c`'s sync, starting one when none is in flight.
    fn step(&mut self, c: usize) -> Result<(), TestCaseError> {
        let now = self.tick();
        let step = match self.flights[c].take() {
            None => {
                let client = &mut self.clients[c];
                let started = client.state.clone();
                let mut machine = sync(started.clone(), client.keys(), background(), client.rng());
                let step = machine.start(now);
                let revisions = self.server.revisions.len();
                self.flights[c] = Some(InFlight {
                    machine,
                    started,
                    step,
                    revisions,
                });
                return Ok(());
            }
            Some(f) => f,
        };
        let InFlight {
            mut machine,
            started,
            step,
            revisions,
        } = step;
        match step {
            Step::Request(r) => {
                let token = self.clients[c].token.clone();
                let resp = self.server.handle(&token, &r).expect("never unreachable");
                let step = machine.step(Input::Response(resp), now);
                self.flights[c] = Some(InFlight {
                    machine,
                    started,
                    step,
                    revisions,
                });
            }
            Step::Done(finished) => {
                match &finished.result {
                    Ok(_) => {}
                    Err(ClientError::Conflicts) => {
                        // Five `412` responses need at least five pushes by other clients.
                        prop_assert!(
                            self.server.revisions.len() >= revisions + 5,
                            "gave up without a race"
                        );
                        self.conflicts += 1;
                    }
                    Err(e) => return Err(TestCaseError::fail(format!("sync failed: {e:?}"))),
                }
                self.clients[c].commit_as(&started, &finished, true, now);
                let g = self.clients[c].state.accepted.as_ref().unwrap().generation;
                prop_assert!(g >= self.accepted[c], "accepted generation went down");
                self.accepted[c] = g;
            }
            Step::Prompt(p) => return Err(TestCaseError::fail(format!("background prompt {p:?}"))),
            Step::Save(_) => return Err(TestCaseError::fail("background save")),
        }
        Ok(())
    }

    fn finish_flights(&mut self) -> Result<(), TestCaseError> {
        for c in 0..self.clients.len() {
            while self.flights[c].is_some() {
                self.step(c)?;
            }
        }
        Ok(())
    }

    fn full_sync(&mut self, c: usize) -> Result<(), TestCaseError> {
        self.step(c)?;
        while self.flights[c].is_some() {
            self.step(c)?;
        }
        Ok(())
    }
}

fn check(n: usize, ops: Vec<Op>) -> Result<(), TestCaseError> {
    let mut w = World::new(n);
    for op in ops {
        match op {
            Op::Edit(c, a) => w.edit(c, a),
            Op::Step(c) => w.step(c)?,
        }
    }
    w.finish_flights()?;
    for _ in 0..2 {
        for c in 0..n {
            w.full_sync(c)?;
        }
    }

    let current = w.server.current_file();
    for (i, c) in w.clients.iter().enumerate() {
        prop_assert!(c.state.file == current, "client {i} did not converge");
        prop_assert!(!c.state.unpushed());
        prop_assert!(c.state.stopped.is_none());
    }
    let vk = w.clients[0].vk.as_ref().unwrap();
    let (_, body) = open_file(&current, vk).unwrap();
    // An item ever deleted is present exactly when its newest stamp is an edit.
    for id in &w.deleted {
        let newest = w.stamps[id].iter().max_by(|a, b| a.0.cmp(&b.0)).unwrap();
        prop_assert_eq!(
            body.item(id).is_some(),
            newest.1,
            "item {} against its delete",
            id
        );
    }
    for (id, set) in &w.passwords {
        if w.deleted.contains(id) {
            continue;
        }
        let item = body.item(id);
        prop_assert!(item.is_some(), "item {id} lost");
        let f = item.unwrap().fields().unwrap();
        let mut kept: Vec<&str> = f
            .password_history
            .iter()
            .map(|h| h.password.as_str())
            .collect();
        kept.push(&f.login.as_ref().unwrap().password);
        for p in set {
            prop_assert!(kept.contains(&p.as_str()), "password {p} of {id} lost");
        }
    }
    let generations: Vec<u64> = w
        .server
        .revisions
        .iter()
        .map(|r| read_header(&r.file).unwrap().generation)
        .collect();
    prop_assert!(
        generations.windows(2).all(|g| g[0] < g[1]),
        "server generations {generations:?}"
    );
    Ok(())
}

proptest! {
    #[test]
    fn clients_converge_without_losing_passwords(
        (n, ops) in (2usize..=3).prop_flat_map(|n| (Just(n), proptest::collection::vec(op(n), 0..80)))
    ) {
        check(n, ops)?;
    }
}

/// A fixed interleaving: both clients pull, both edit the same item, and their pushes race.
#[test]
fn racing_password_changes_keep_both_passwords() {
    let ops = vec![
        Op::Edit(0, Action::Add),
        Op::Step(0),
        Op::Step(0),
        Op::Step(0),
        Op::Step(0),
        Op::Step(1),
        Op::Step(1),
        Op::Step(1),
        Op::Step(0),
        Op::Step(1),
        Op::Edit(0, Action::SetPassword(0)),
        Op::Edit(1, Action::SetPassword(0)),
        Op::Step(0),
        Op::Step(1),
        Op::Step(0),
        Op::Step(1),
        Op::Step(0),
        Op::Step(1),
        Op::Step(0),
        Op::Step(1),
    ];
    check(2, ops).unwrap();
}
