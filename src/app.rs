//! The egui front end. It owns no wallet logic: it renders a snapshot of the
//! store each frame and hands every network operation to the tokio runtime,
//! collecting results over a channel.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, TextureHandle, TextureOptions};

use crate::http::Http;
use crate::keys;
use crate::store::{MintState, Note, NoteStatus, Store, WalletData, MIN_PASSWORD_LEN};
use crate::wallet::{export_forms, msat_to_sats, Wallet, PUBLIC_MINTS};

/// How often waiting mints are asked whether their invoice was paid.
const MINT_POLL_EVERY: Duration = Duration::from_secs(4);
/// How often registered Lightning Addresses are checked for payments.
const ADDRESS_POLL_EVERY: Duration = Duration::from_secs(20);

enum Screen {
    Locked {
        password: String,
        confirm: String,
        error: Option<String>,
        unlocking: Option<Receiver<Result<Store, String>>>,
    },
    Unlocked(Wallet),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Notes,
    Mint,
    Mints,
    Seed,
}

struct Message {
    ok: bool,
    text: String,
}

struct MeltForm {
    id: String,
    amount_msat: u64,
    destination: String,
}

/// Pay from one mint's notes: an invoice, a Lightning Address, or a cx1.
struct PayForm {
    origin: String,
    destination: String,
    amount: String,
}

/// Carve a note of an exact amount out of one mint's notes, to hand over.
struct SendForm {
    origin: String,
    amount: String,
}

/// First unlock of a wallet with no seed: make one, or bring one back.
#[derive(Default)]
struct SeedSetup {
    generated: Option<String>,
    written_down: bool,
    restore_input: String,
}

type OpResult = (String, Result<String, String>);

enum Action {
    Receive { trust_new: bool },
    Check(String),
    Rotate(String),
    Resolve(String),
    OpenMelt(String, u64),
    Melt,
    Export(String),
    MarkSent(String),
    Remove(String),
    Unpin(String),
    Trust(String),
    Untrust(String),
    StartMint,
    DismissMint(String),
    UseSeed(String),
    RestoreSeed(String),
    Restore,
    OpenPay,
    Pay,
    OpenSend,
    SendAmount,
    Merge(String),
    Register(String),
    Unregister(String, String),
    Lock,
}

pub struct App {
    runtime: tokio::runtime::Runtime,
    path: PathBuf,
    screen: Screen,
    tab: Tab,
    results: (Sender<OpResult>, Receiver<OpResult>),
    /// Keys of operations in flight: a note id, "receive", "mint", "poll",
    /// "restore", or "trust:<address>".
    busy: HashSet<String>,
    messages: Vec<Message>,
    receive_input: String,
    /// A pasted note whose mint isn't trusted yet: its origin, awaiting a yes.
    confirm_trust: Option<String>,
    melt: Option<MeltForm>,
    export: Option<String>,
    qr_textures: HashMap<String, TextureHandle>,
    seed_setup: SeedSetup,
    show_seed: bool,
    mint_address: String,
    mint_amount: String,
    custom_mint: String,
    last_poll: Option<Instant>,
    last_address_poll: Option<Instant>,
    pay: Option<PayForm>,
    send: Option<SendForm>,
    /// Username being typed per mint origin, for registering an address.
    usernames: HashMap<String, String>,
}

impl App {
    pub fn new(path: PathBuf) -> Self {
        App {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("a tokio runtime"),
            path,
            screen: locked(None),
            tab: Tab::Notes,
            results: channel(),
            busy: HashSet::new(),
            messages: Vec::new(),
            receive_input: String::new(),
            confirm_trust: None,
            melt: None,
            export: None,
            qr_textures: HashMap::new(),
            seed_setup: SeedSetup::default(),
            show_seed: false,
            mint_address: PUBLIC_MINTS[0].to_string(),
            mint_amount: String::new(),
            custom_mint: String::new(),
            last_poll: None,
            last_address_poll: None,
            pay: None,
            send: None,
            usernames: HashMap::new(),
        }
    }

    fn spawn<F>(&mut self, ctx: &egui::Context, key: String, operation: F)
    where
        F: Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        self.busy.insert(key.clone());
        let tx = self.results.0.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            let result = operation.await.map_err(|e| format!("{e:#}"));
            let _ = tx.send((key, result));
            ctx.request_repaint();
        });
    }

    fn push(&mut self, ok: bool, text: String) {
        self.messages.push(Message { ok, text });
        if self.messages.len() > 20 {
            self.messages.remove(0);
        }
    }

    fn collect_results(&mut self) {
        while let Ok((key, result)) = self.results.1.try_recv() {
            self.busy.remove(&key);
            match result {
                // a quiet poll has nothing to say
                Ok(text) if text.is_empty() => {}
                // a carved note comes back as its id: show it for handing over
                Ok(id) if key == "carve" => {
                    self.export = Some(id);
                    self.push(
                        true,
                        "Here is your note - hand it over, then mark it given away.".into(),
                    );
                }
                Ok(text) => {
                    match key.as_str() {
                        "receive" => self.receive_input.clear(),
                        "mint" => self.mint_amount.clear(),
                        _ => {}
                    }
                    self.push(true, text)
                }
                Err(text) => self.push(false, text),
            }
        }
    }

    /// Ask the mint about every waiting mint, a few seconds apart.
    fn poll_mints(&mut self, ctx: &egui::Context, wallet: &Wallet, data: &WalletData) {
        let waiting: Vec<String> = data
            .pending_mints
            .iter()
            .filter(|m| m.state == MintState::Waiting && m.pr.is_some())
            .map(|m| m.output.clone())
            .collect();
        if waiting.is_empty() {
            return;
        }
        ctx.request_repaint_after(MINT_POLL_EVERY);
        if self.busy.contains("poll")
            || self
                .last_poll
                .is_some_and(|t| t.elapsed() < MINT_POLL_EVERY)
        {
            return;
        }
        self.last_poll = Some(Instant::now());
        let w = wallet.clone();
        self.spawn(ctx, "poll".into(), async move {
            let mut credited = Vec::new();
            for output in waiting {
                // one unreachable mint must not hide another's note
                if let Ok(Some(message)) = w.poll_mint(&output).await {
                    credited.push(message);
                }
            }
            Ok(credited.join(" "))
        });
    }

    /// Look for payments to registered addresses now and then.
    fn poll_addresses(&mut self, ctx: &egui::Context, wallet: &Wallet, data: &WalletData) {
        if data.addresses.is_empty() {
            return;
        }
        ctx.request_repaint_after(ADDRESS_POLL_EVERY);
        if self.busy.contains("address-poll")
            || self
                .last_address_poll
                .is_some_and(|t| t.elapsed() < ADDRESS_POLL_EVERY)
        {
            return;
        }
        self.last_address_poll = Some(Instant::now());
        let w = wallet.clone();
        self.spawn(ctx, "address-poll".into(), async move {
            // unreachable mints stay quiet here; the next poll tries again
            Ok(w.check_addresses().await.unwrap_or_default())
        });
    }

    // ---- locked ----

    fn locked_ui(&mut self, ui: &mut egui::Ui) {
        let exists = Store::exists(&self.path);
        let path = self.path.clone();
        let Screen::Locked {
            password,
            confirm,
            error,
            unlocking,
        } = &mut self.screen
        else {
            return;
        };

        if let Some(rx) = unlocking {
            match rx.try_recv() {
                Ok(Ok(store)) => {
                    self.screen = Screen::Unlocked(Wallet::new(store, Http::default()));
                    return;
                }
                Ok(Err(e)) => {
                    *error = Some(e);
                    *unlocking = None;
                }
                Err(_) => {}
            }
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading(RichText::new("LNURLwallet").size(32.0).strong());
                ui.label("Bearer notes on Lightning (LNURLcash, LUD-25)");
                ui.add_space(24.0);

                ui.set_max_width(320.0);
                if exists {
                    ui.label("Enter your password to unlock the wallet.");
                } else {
                    ui.label("No wallet yet. Choose a password to encrypt it on this device.");
                    ui.label(
                        RichText::new(
                            "Next you'll set up the seed phrase that backs up your notes.",
                        )
                        .small()
                        .weak(),
                    );
                }
                ui.add_space(8.0);
                let first = ui.add(
                    egui::TextEdit::singleline(password)
                        .password(true)
                        .hint_text("password"),
                );
                let mut submit =
                    first.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if !exists {
                    let second = ui.add(
                        egui::TextEdit::singleline(confirm)
                            .password(true)
                            .hint_text("repeat password"),
                    );
                    submit |= second.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                }
                ui.add_space(8.0);
                let busy = unlocking.is_some();
                let label = if exists { "Unlock" } else { "Create wallet" };
                submit |= ui.add_enabled(!busy, egui::Button::new(label)).clicked();
                if busy {
                    ui.spinner();
                }
                if let Some(e) = error.as_ref() {
                    ui.colored_label(Color32::from_rgb(220, 80, 80), e);
                }
                ui.add_space(16.0);
                ui.label(RichText::new(path.display().to_string()).small().weak());

                if submit && !busy {
                    if !exists && password != confirm {
                        *error = Some("the passwords don't match".into());
                    } else if !exists && password.chars().count() < MIN_PASSWORD_LEN {
                        *error = Some(format!("use at least {MIN_PASSWORD_LEN} characters"));
                    } else {
                        let (tx, rx) = channel();
                        let pw = std::mem::take(password);
                        confirm.clear();
                        *error = None;
                        let ctx = ui.ctx().clone();
                        // argon2 takes a moment; keep the window responsive
                        std::thread::spawn(move || {
                            let result = if exists {
                                Store::open(&path, &pw)
                            } else {
                                Store::create(&path, &pw)
                            };
                            let _ = tx.send(result.map_err(|e| format!("{e:#}")));
                            ctx.request_repaint();
                        });
                        *unlocking = Some(rx);
                    }
                }
            });
        });
    }

    // ---- seed setup ----

    fn seed_setup_ui(&mut self, ui: &mut egui::Ui) -> Vec<Action> {
        let mut actions = Vec::new();
        self.messages_panel(ui);
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading(RichText::new("Seed phrase").strong());
                ui.label(
                    "Every note this wallet mints or rotates is a key derived from 12 words. \
                     With them, a new install finds your notes again at each mint.",
                );
                ui.add_space(12.0);

                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.strong("Create a new seed");
                    let setup = &mut self.seed_setup;
                    match &setup.generated {
                        None => {
                            if ui.button("Generate 12 words").clicked() {
                                setup.generated = Some(keys::generate_phrase());
                            }
                        }
                        Some(phrase) => {
                            seed_words(ui, phrase);
                            ui.colored_label(
                                Color32::from_rgb(230, 150, 40),
                                "Write these down, in order, on paper. Anyone who has them can spend your notes.",
                            );
                            ui.checkbox(&mut setup.written_down, "I've written them down");
                            if ui
                                .add_enabled(setup.written_down, egui::Button::new("Use this seed"))
                                .clicked()
                            {
                                actions.push(Action::UseSeed(phrase.clone()));
                            }
                        }
                    }
                });
                ui.add_space(12.0);

                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.strong("Restore from a seed");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.seed_setup.restore_input)
                            .hint_text("your 12 words")
                            .desired_rows(2)
                            .desired_width(f32::INFINITY),
                    );
                    ui.label(
                        RichText::new("Scans every trusted and public mint for notes this seed derives.")
                            .small()
                            .weak(),
                    );
                    let ready = !self.seed_setup.restore_input.trim().is_empty();
                    if ui.add_enabled(ready, egui::Button::new("Restore")).clicked() {
                        actions.push(Action::RestoreSeed(self.seed_setup.restore_input.clone()));
                    }
                });
                ui.add_space(12.0);
                if ui.button("Lock").clicked() {
                    actions.push(Action::Lock);
                }
            });
        });
        actions
    }

    // ---- unlocked ----

    fn messages_panel(&self, ui: &mut egui::Ui) {
        egui::Panel::bottom("messages").show(ui, |ui| {
            ui.add_space(4.0);
            if self.messages.is_empty() {
                ui.label(RichText::new("Ready.").weak());
            }
            let start = self.messages.len().saturating_sub(3);
            for message in &self.messages[start..] {
                let color = if message.ok {
                    ui.visuals().text_color()
                } else {
                    Color32::from_rgb(220, 80, 80)
                };
                ui.colored_label(color, &message.text);
            }
            ui.add_space(4.0);
        });
    }

    fn wallet_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) -> Vec<Action> {
        let mut actions = Vec::new();
        let data = wallet.store().data.clone();
        self.poll_mints(ui.ctx(), wallet, &data);
        self.poll_addresses(ui.ctx(), wallet, &data);

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("LNURLwallet").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock").clicked() {
                        actions.push(Action::Lock);
                    }
                    ui.label(
                        RichText::new(format!("{} sats", msat_to_sats(data.live_balance_msat())))
                            .size(22.0)
                            .strong(),
                    );
                });
            });
            ui.horizontal(|ui| {
                let waiting = data
                    .pending_mints
                    .iter()
                    .filter(|m| m.state == MintState::Waiting)
                    .count();
                let mint_label = if waiting > 0 {
                    format!("Mint ({waiting})")
                } else {
                    "Mint".into()
                };
                for (tab, label) in [
                    (Tab::Notes, "Notes".to_string()),
                    (Tab::Mint, mint_label),
                    (Tab::Mints, format!("Mints ({})", data.mints.len())),
                    (Tab::Seed, "Seed".to_string()),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.tab = tab;
                    }
                }
            });
            ui.add_space(4.0);
        });

        self.messages_panel(ui);

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Notes => self.notes_tab(ui, &data, &mut actions),
                Tab::Mint => self.mint_tab(ui, &data, &mut actions),
                Tab::Mints => self.mints_tab(ui, &data, &mut actions),
                Tab::Seed => self.seed_tab(ui, wallet, &data, &mut actions),
            });
        });

        self.trust_window(ui.ctx(), &mut actions);
        self.melt_window(ui.ctx(), &mut actions);
        self.pay_window(ui.ctx(), &data, &mut actions);
        self.send_window(ui.ctx(), &data, &mut actions);
        self.export_window(ui.ctx(), &data.notes, &mut actions);
        actions
    }

    fn notes_tab(&mut self, ui: &mut egui::Ui, data: &WalletData, actions: &mut Vec<Action>) {
        ui.group(|ui| {
            ui.strong("Receive a note");
            ui.horizontal(|ui| {
                let busy = self.busy.contains("receive");
                let field = ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.receive_input)
                        .hint_text("lnurlw://…  or  LNURL1…")
                        .desired_width(ui.available_width() - 90.0),
                );
                let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let ready = !busy && !self.receive_input.trim().is_empty();
                if ui.add_enabled(ready, egui::Button::new("Receive")).clicked() || (enter && ready) {
                    actions.push(Action::Receive { trust_new: false });
                }
                if busy {
                    ui.spinner();
                }
            });
            ui.label(
                RichText::new("The note is checked with its mint and rotated onto one of your seed keys at once, so the sender's copy stops working.")
                    .small()
                    .weak(),
            );
        });

        ui.add_space(8.0);
        let balances = mint_balances(data);
        ui.horizontal(|ui| {
            let funded = !balances.is_empty();
            let busy = self.busy.contains("pay") || self.busy.contains("carve");
            if ui
                .add_enabled(funded && !busy, egui::Button::new("Pay…"))
                .on_hover_text("Any amount, to an invoice, a Lightning Address or a cx1")
                .clicked()
            {
                actions.push(Action::OpenPay);
            }
            if ui
                .add_enabled(funded && !busy, egui::Button::new("Send amount…"))
                .on_hover_text("Make a note of exactly that amount to hand over")
                .clicked()
            {
                actions.push(Action::OpenSend);
            }
            if busy {
                ui.spinner();
            }
        });
        for (origin, total, count) in &balances {
            ui.horizontal(|ui| {
                ui.label(RichText::new(lnurlcash_core::server_of(origin)).weak());
                ui.label(format!(
                    "{} sats in {count} note{}",
                    msat_to_sats(*total),
                    if *count == 1 { "" } else { "s" }
                ));
                if *count > 1 {
                    let busy = self.busy.contains(&format!("merge:{origin}"));
                    if ui
                        .add_enabled(!busy, egui::Button::new("Merge").small())
                        .on_hover_text("Combine them into one note")
                        .clicked()
                    {
                        actions.push(Action::Merge(origin.clone()));
                    }
                }
            });
        }

        ui.add_space(8.0);
        let (active, spent): (Vec<&Note>, Vec<&Note>) = data
            .notes
            .iter()
            .partition(|n| n.status != NoteStatus::Spent);
        ui.strong(format!("Notes ({})", active.len()));
        if active.is_empty() {
            ui.label(
                RichText::new("No notes yet. Receive one, or mint one in the Mint tab.").weak(),
            );
        }
        for note in &active {
            self.note_row(ui, note, actions);
        }
        if !spent.is_empty() {
            egui::CollapsingHeader::new(format!("Spent ({})", spent.len()))
                .id_salt("spent")
                .show(ui, |ui| {
                    for note in &spent {
                        self.note_row(ui, note, actions);
                    }
                });
        }

        ui.add_space(8.0);
        egui::CollapsingHeader::new("Activity")
            .id_salt("activity")
            .show(ui, |ui| {
                for entry in data.activity.iter().rev().take(100) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format_time(entry.at))
                                .small()
                                .weak()
                                .monospace(),
                        );
                        ui.label(RichText::new(&entry.text).small());
                    });
                }
            });
    }

    fn mint_tab(&mut self, ui: &mut egui::Ui, data: &WalletData, actions: &mut Vec<Action>) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.strong("Mint a note");
            ui.label(
                RichText::new("Pay a Lightning invoice from any wallet; the mint credits a note to your next seed key.")
                    .small()
                    .weak(),
            );
            let mut choices: Vec<String> = data.mints.iter().filter_map(|m| m.address.clone()).collect();
            for public in PUBLIC_MINTS {
                if !choices.iter().any(|c| c == public) {
                    choices.push(public.to_string());
                }
            }
            ui.horizontal(|ui| {
                ui.label("Mint");
                egui::ComboBox::from_id_salt("mint-choice")
                    .selected_text(&self.mint_address)
                    .width(260.0)
                    .show_ui(ui, |ui| {
                        for choice in &choices {
                            let trusted = data.mints.iter().any(|m| m.address.as_deref() == Some(choice));
                            let label = if trusted { format!("{choice}  ✓") } else { choice.clone() };
                            ui.selectable_value(&mut self.mint_address, choice.clone(), label);
                        }
                    });
            });
            ui.horizontal(|ui| {
                ui.label("Amount");
                ui.add(
                    egui::TextEdit::singleline(&mut self.mint_amount)
                        .hint_text("sats")
                        .desired_width(120.0),
                );
                ui.label("sats");
            });
            let amount_ok = self.mint_amount.trim().parse::<u64>().is_ok_and(|a| a > 0);
            let busy = self.busy.contains("mint");
            ui.horizontal(|ui| {
                if ui.add_enabled(amount_ok && !busy, egui::Button::new("Get invoice")).clicked() {
                    actions.push(Action::StartMint);
                }
                if busy {
                    ui.spinner();
                }
            });
            if !data.mints.iter().any(|m| m.address.as_deref() == Some(self.mint_address.as_str())) {
                ui.label(
                    RichText::new("Minting here also trusts this mint: it will hold the sats behind your note.")
                        .small()
                        .color(Color32::from_rgb(230, 150, 40)),
                );
            }
        });

        ui.add_space(8.0);
        let waiting: Vec<_> = data
            .pending_mints
            .iter()
            .filter(|m| m.state == MintState::Waiting)
            .collect();
        ui.strong(format!("Waiting for payment ({})", waiting.len()));
        if waiting.is_empty() {
            ui.label(RichText::new("Nothing to pay.").weak());
        }
        for pending in waiting {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{} sats", msat_to_sats(pending.paid_msat)))
                            .size(18.0)
                            .strong(),
                    );
                    ui.label(RichText::new(&pending.address).weak());
                    if self.busy.contains("poll") {
                        ui.spinner();
                    }
                });
                ui.label(
                    RichText::new(format!(
                        "The note will hold {} sats after the mint's fee.",
                        msat_to_sats(pending.expected_msat)
                    ))
                    .small()
                    .weak(),
                );
                match &pending.pr {
                    Some(pr) => {
                        let qr = pr.to_ascii_uppercase();
                        let texture = self
                            .qr_textures
                            .entry(qr.clone())
                            .or_insert_with(|| {
                                ui.ctx().load_texture("invoice-qr", qr_image(&qr), TextureOptions::NEAREST)
                            })
                            .clone();
                        ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(240.0, 240.0)));
                        ui.horizontal(|ui| {
                            if ui.button("Copy invoice").clicked() {
                                ui.ctx().copy_text(pr.clone());
                            }
                            if ui
                                .button("Dismiss")
                                .on_hover_text("Stop waiting. If it gets paid anyway, a seed restore finds the note.")
                                .clicked()
                            {
                                actions.push(Action::DismissMint(pending.output.clone()));
                            }
                        });
                    }
                    None => {
                        ui.label(RichText::new("No invoice was issued.").weak());
                        if ui.button("Dismiss").clicked() {
                            actions.push(Action::DismissMint(pending.output.clone()));
                        }
                    }
                }
            });
        }
    }

    fn mints_tab(&mut self, ui: &mut egui::Ui, data: &WalletData, actions: &mut Vec<Action>) {
        ui.label(
            RichText::new(
                "A note is only as good as the mint that issued it: the mint holds the sats. \
                 Receiving and minting only happen at mints you trust.",
            )
            .small()
            .weak(),
        );
        ui.add_space(6.0);
        ui.strong("Public mints");
        for address in PUBLIC_MINTS {
            ui.horizontal(|ui| {
                ui.label(address);
                let trusted = data
                    .mints
                    .iter()
                    .any(|m| m.address.as_deref() == Some(address));
                if trusted {
                    ui.label(RichText::new("trusted").color(status_color(NoteStatus::Live)));
                } else {
                    let key = format!("trust:{address}");
                    let busy = self.busy.contains(&key);
                    if ui.add_enabled(!busy, egui::Button::new("Trust")).clicked() {
                        actions.push(Action::Trust(address.to_string()));
                    }
                    if busy {
                        ui.spinner();
                    }
                }
            });
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.custom_mint)
                    .hint_text("another mint: mint@example.com")
                    .desired_width(260.0),
            );
            let ready = !self.custom_mint.trim().is_empty();
            if ui.add_enabled(ready, egui::Button::new("Trust")).clicked() {
                actions.push(Action::Trust(self.custom_mint.trim().to_string()));
            }
        });

        ui.add_space(10.0);
        ui.strong(format!("Trusted ({})", data.mints.len()));
        if data.mints.is_empty() {
            ui.label(RichText::new("None yet.").weak());
        }
        for mint in &data.mints {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.strong(mint.address.as_deref().unwrap_or(&mint.origin));
                    let held: u64 = data
                        .notes
                        .iter()
                        .filter(|n| {
                            n.status == NoteStatus::Live
                                && crate::wallet::origin_of(&n.url) == mint.origin
                        })
                        .map(|n| n.amount_msat)
                        .sum();
                    ui.label(RichText::new(format!("{} sats held", msat_to_sats(held))).weak());
                });
                ui.horizontal(|ui| {
                    match data.mint_keys.get(&mint.origin) {
                        Some(key) => {
                            ui.label(RichText::new("key").small().weak());
                            ui.monospace(RichText::new(short(key)).small())
                                .on_hover_text(key);
                            if ui
                                .small_button("Unpin key")
                                .on_hover_text("Only if the mint really changed its signing key")
                                .clicked()
                            {
                                actions.push(Action::Unpin(mint.origin.clone()));
                            }
                        }
                        None => {
                            ui.label(RichText::new("key pinned on first note").small().weak());
                        }
                    }
                    if ui.small_button("Untrust").clicked() {
                        actions.push(Action::Untrust(mint.origin.clone()));
                    }
                });

                // Lightning Addresses registered here against this seed
                let host = lnurlcash_core::server_of(&mint.origin);
                for address in data.addresses.iter().filter(|a| a.origin == mint.origin) {
                    ui.horizontal(|ui| {
                        let full = format!("{}@{host}", address.username);
                        ui.label(RichText::new(&full).strong());
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(full.clone());
                        }
                        let key = format!("unregister:{}:{}", mint.origin, address.username);
                        if ui
                            .add_enabled(!self.busy.contains(&key), egui::Button::new("Unregister").small())
                            .clicked()
                        {
                            actions.push(Action::Unregister(mint.origin.clone(), address.username.clone()));
                        }
                    });
                }
                ui.horizontal(|ui| {
                    let username = self.usernames.entry(mint.origin.clone()).or_default();
                    ui.add(
                        egui::TextEdit::singleline(username)
                            .hint_text("username")
                            .desired_width(120.0),
                    );
                    ui.label(RichText::new(format!("@{host}")).weak());
                    let key = format!("register:{}", mint.origin);
                    let busy = self.busy.contains(&key);
                    let ready = !username.trim().is_empty() && !busy;
                    if ui
                        .add_enabled(ready, egui::Button::new("Register").small())
                        .on_hover_text(
                            "Get a Lightning Address here: every payment to it mints a note to your seed, \
                             and wallets at this mint can pay it without Lightning",
                        )
                        .clicked()
                    {
                        actions.push(Action::Register(mint.origin.clone()));
                    }
                    if busy {
                        ui.spinner();
                    }
                });
            });
        }
    }

    fn pay_window(&mut self, ctx: &egui::Context, data: &WalletData, actions: &mut Vec<Action>) {
        let Some(form) = &mut self.pay else { return };
        let balances = mint_balances(data);
        let mut open = true;
        egui::Window::new("Pay")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                mint_picker(ui, "pay-from", &mut form.origin, &balances);
                ui.add(
                    egui::TextEdit::multiline(&mut form.destination)
                        .hint_text("lnbc…  or  name@domain  or  cx1…")
                        .desired_rows(3)
                        .desired_width(380.0),
                );
                let invoiced = lnurlcash_core::decode_bolt11_amount_msat(form.destination.trim());
                ui.horizontal(|ui| {
                    ui.label("Amount");
                    match invoiced {
                        Some(msat) => {
                            ui.label(format!("{} sats (from the invoice)", msat_to_sats(msat)));
                        }
                        None => {
                            ui.add(
                                egui::TextEdit::singleline(&mut form.amount)
                                    .hint_text("sats")
                                    .desired_width(120.0),
                            );
                        }
                    }
                });
                ui.label(
                    RichText::new(
                        "Notes are split or merged to the exact amount first. A Lightning Address \
                         registered at this same mint is paid inside the mint, with no Lightning payment.",
                    )
                    .small()
                    .weak(),
                );
                let amount_ok = invoiced.is_some() || form.amount.trim().parse::<u64>().is_ok_and(|a| a > 0);
                let ready = amount_ok && !form.destination.trim().is_empty() && !form.origin.is_empty();
                if ui.add_enabled(ready, egui::Button::new("Pay")).clicked() {
                    actions.push(Action::Pay);
                }
            });
        if !open {
            self.pay = None;
        }
    }

    fn send_window(&mut self, ctx: &egui::Context, data: &WalletData, actions: &mut Vec<Action>) {
        let Some(form) = &mut self.send else { return };
        let balances = mint_balances(data);
        let mut open = true;
        egui::Window::new("Send an amount")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                mint_picker(ui, "send-from", &mut form.origin, &balances);
                ui.horizontal(|ui| {
                    ui.label("Amount");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.amount)
                            .hint_text("sats")
                            .desired_width(120.0),
                    );
                    ui.label("sats");
                });
                ui.label(
                    RichText::new("Makes a note of exactly this amount (your change stays with you), then shows it to hand over.")
                        .small()
                        .weak(),
                );
                let ready = form.amount.trim().parse::<u64>().is_ok_and(|a| a > 0) && !form.origin.is_empty();
                if ui.add_enabled(ready, egui::Button::new("Make note")).clicked() {
                    actions.push(Action::SendAmount);
                }
            });
        if !open {
            self.send = None;
        }
    }

    fn seed_tab(
        &mut self,
        ui: &mut egui::Ui,
        wallet: &Wallet,
        data: &WalletData,
        actions: &mut Vec<Action>,
    ) {
        ui.strong("Seed phrase");
        ui.label(
            RichText::new("The backup for every note this wallet minted or rotated. The password only protects this device's copy.")
                .small()
                .weak(),
        );
        if self.show_seed {
            if let Some(phrase) = wallet.seed_phrase() {
                seed_words(ui, &phrase);
            }
            if ui.button("Hide").clicked() {
                self.show_seed = false;
            }
        } else if ui.button("Show seed phrase").clicked() {
            self.show_seed = true;
        }

        ui.add_space(10.0);
        ui.strong("Restore");
        ui.label(
            RichText::new(
                "Ask every trusted and public mint about each key your seed derives. \
                 Finds notes this device lost track of.",
            )
            .small()
            .weak(),
        );
        ui.horizontal(|ui| {
            let busy = self.busy.contains("restore");
            if ui
                .add_enabled(!busy, egui::Button::new("Scan mints"))
                .clicked()
            {
                actions.push(Action::Restore);
            }
            if busy {
                ui.spinner();
            }
        });
        if !data.counters.is_empty() {
            egui::CollapsingHeader::new("Key counters")
                .id_salt("counters")
                .show(ui, |ui| {
                    for (domain, [wallet_i, change_i, address_i]) in &data.counters {
                        ui.label(
                            RichText::new(format!("{domain}: wallet {wallet_i}, change {change_i}, address {address_i}"))
                                .small()
                                .monospace(),
                        );
                    }
                });
        }
        ui.add_space(10.0);
        ui.label(
            RichText::new(wallet.store().path().display().to_string())
                .small()
                .weak(),
        );
    }

    fn note_row(&self, ui: &mut egui::Ui, note: &Note, actions: &mut Vec<Action>) {
        let id = note.id();
        let busy = self.busy.contains(&id);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} sats", msat_to_sats(note.amount_msat)))
                        .size(18.0)
                        .strong(),
                );
                ui.label(
                    RichText::new(note.status.label())
                        .color(status_color(note.status))
                        .strong(),
                );
                if !note.verified {
                    ui.label(RichText::new("unverified").color(Color32::from_rgb(230, 150, 40)))
                        .on_hover_text(
                            "The amount hasn't been confirmed by the mint yet - Check it.",
                        );
                }
                if note.k1().starts_with("ck1") {
                    ui.label(RichText::new("seed").small().weak())
                        .on_hover_text("A key-path note: recoverable from your seed phrase");
                }
                ui.label(RichText::new(note.mint()).weak());
            });
            if let Some(detail) = &note.detail {
                ui.label(RichText::new(detail).small().weak());
            }
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    let s = note.status;
                    if s == NoteStatus::Uncertain {
                        if ui
                            .button("Resolve")
                            .on_hover_text("Ask the mint which secret is the note now")
                            .clicked()
                        {
                            actions.push(Action::Resolve(id.clone()));
                        }
                    } else if ui
                        .button("Check")
                        .on_hover_text("Ask the mint what this note is worth")
                        .clicked()
                    {
                        actions.push(Action::Check(id.clone()));
                    }
                    if matches!(s, NoteStatus::Live | NoteStatus::Sent) {
                        let (label, hint) = if s == NoteStatus::Sent {
                            (
                                "Take back",
                                "Rotate it - works only if the recipient hasn't claimed it",
                            )
                        } else {
                            ("Rotate", "Move it onto your next seed key")
                        };
                        if ui.button(label).on_hover_text(hint).clicked() {
                            actions.push(Action::Rotate(id.clone()));
                        }
                    }
                    if s == NoteStatus::Live {
                        if ui
                            .button("Melt")
                            .on_hover_text("Pay a Lightning invoice or address with it")
                            .clicked()
                        {
                            actions.push(Action::OpenMelt(id.clone(), note.amount_msat));
                        }
                        if ui
                            .button("Send")
                            .on_hover_text("Show it as a QR code / link to hand over")
                            .clicked()
                        {
                            actions.push(Action::Export(id.clone()));
                        }
                    }
                    if s == NoteStatus::Spent && ui.button("Remove").clicked() {
                        actions.push(Action::Remove(id.clone()));
                    }
                });
                if busy {
                    ui.spinner();
                }
            });
        });
    }

    fn trust_window(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        let Some(origin) = self.confirm_trust.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new("Trust this mint?")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(format!("This note was issued by {origin}, which you don't trust yet."));
                ui.label(
                    RichText::new(
                        "A note is a claim on that mint: it's only worth something if the mint pays out. \
                         Trust it only if you'd hold sats there.",
                    )
                    .small()
                    .weak(),
                );
                ui.horizontal(|ui| {
                    if ui.button("Trust and receive").clicked() {
                        actions.push(Action::Receive { trust_new: true });
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_trust = None;
                    }
                });
            });
        if !open {
            self.confirm_trust = None;
        }
    }

    fn melt_window(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        let Some(form) = &mut self.melt else { return };
        let mut open = true;
        egui::Window::new("Melt note")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Pay exactly {} sats. Paste an invoice for that amount, or a Lightning Address to request one.",
                    msat_to_sats(form.amount_msat)
                ));
                ui.add(
                    egui::TextEdit::multiline(&mut form.destination)
                        .hint_text("lnbc…  or  name@domain")
                        .desired_rows(3)
                        .desired_width(380.0),
                );
                ui.label(
                    RichText::new("The mint pays asynchronously: OK means in flight, not done. Check the note later to confirm.")
                        .small()
                        .weak(),
                );
                let ready = !form.destination.trim().is_empty() && !self.busy.contains(&form.id);
                if ui.add_enabled(ready, egui::Button::new(format!("Melt {} sats", msat_to_sats(form.amount_msat)))).clicked() {
                    actions.push(Action::Melt);
                }
            });
        if !open {
            self.melt = None;
        }
    }

    fn export_window(&mut self, ctx: &egui::Context, notes: &[Note], actions: &mut Vec<Action>) {
        let Some(id) = self.export.clone() else {
            return;
        };
        let Some(note) = notes.iter().find(|n| n.id() == id) else {
            self.export = None;
            return;
        };
        let (link, qr) = export_forms(note);
        let texture = self
            .qr_textures
            .entry(qr.clone())
            .or_insert_with(|| ctx.load_texture("note-qr", qr_image(&qr), TextureOptions::NEAREST))
            .clone();
        let mut open = true;
        egui::Window::new(format!("Send {} sats", msat_to_sats(note.amount_msat)))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.colored_label(
                    Color32::from_rgb(230, 150, 40),
                    "This is the money itself: anyone who scans or copies it can spend it.",
                );
                ui.vertical_centered(|ui| {
                    ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(300.0, 300.0)));
                });
                ui.horizontal(|ui| {
                    if ui.button("Copy link").clicked() {
                        ctx.copy_text(link.clone());
                    }
                    if ui.button("Copy LNURL").clicked() {
                        ctx.copy_text(qr.clone());
                    }
                    if ui
                        .button("Mark as given away")
                        .on_hover_text("Once handed over. Check shows when it's claimed; Take back works until then.")
                        .clicked()
                    {
                        actions.push(Action::MarkSent(id.clone()));
                    }
                });
            });
        if !open {
            self.export = None;
        }
    }

    fn apply(&mut self, ctx: &egui::Context, wallet: &Wallet, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Receive { trust_new } => {
                    let input = self.receive_input.clone();
                    if !trust_new {
                        if let Some(origin) = Wallet::note_origin(&input) {
                            if !wallet.is_trusted(&origin) {
                                self.confirm_trust = Some(origin);
                                continue;
                            }
                        }
                    }
                    self.confirm_trust = None;
                    let w = wallet.clone();
                    self.spawn(ctx, "receive".into(), async move {
                        w.receive(&input, trust_new).await
                    });
                }
                Action::Check(id) => {
                    let w = wallet.clone();
                    let key = id.clone();
                    self.spawn(ctx, key, async move { w.check(&id).await });
                }
                Action::OpenPay => {
                    let origin = largest_mint(&wallet.store().data);
                    self.pay = Some(PayForm {
                        origin,
                        destination: String::new(),
                        amount: String::new(),
                    });
                }
                Action::Pay => {
                    if let Some(form) = self.pay.take() {
                        let amount = form
                            .amount
                            .trim()
                            .parse::<u64>()
                            .ok()
                            .and_then(|sats| sats.checked_mul(1000));
                        let w = wallet.clone();
                        self.spawn(ctx, "pay".into(), async move {
                            w.pay(&form.origin, &form.destination, amount).await
                        });
                    }
                }
                Action::OpenSend => {
                    let origin = largest_mint(&wallet.store().data);
                    self.send = Some(SendForm {
                        origin,
                        amount: String::new(),
                    });
                }
                Action::SendAmount => {
                    let form = self.send.take();
                    let amount = form
                        .as_ref()
                        .and_then(|f| f.amount.trim().parse::<u64>().ok())
                        .and_then(|sats| sats.checked_mul(1000));
                    if let (Some(form), Some(msat)) = (form, amount) {
                        let w = wallet.clone();
                        self.spawn(ctx, "carve".into(), async move {
                            w.note_for_amount(&form.origin, msat).await
                        });
                    }
                }
                Action::Merge(origin) => {
                    let w = wallet.clone();
                    self.spawn(ctx, format!("merge:{origin}"), async move {
                        w.merge_all(&origin).await
                    });
                }
                Action::Register(origin) => {
                    let username = self.usernames.remove(&origin).unwrap_or_default();
                    let w = wallet.clone();
                    self.spawn(ctx, format!("register:{origin}"), async move {
                        w.register_address(&origin, &username).await
                    });
                }
                Action::Unregister(origin, username) => {
                    let w = wallet.clone();
                    self.spawn(ctx, format!("unregister:{origin}:{username}"), async move {
                        w.unregister_address(&origin, &username).await
                    });
                }
                Action::Rotate(id) => {
                    let w = wallet.clone();
                    let key = id.clone();
                    self.spawn(ctx, key, async move { w.rotate(&id).await });
                }
                Action::Resolve(id) => {
                    let w = wallet.clone();
                    let key = id.clone();
                    self.spawn(ctx, key, async move { w.resolve(&id).await });
                }
                Action::OpenMelt(id, amount_msat) => {
                    self.melt = Some(MeltForm {
                        id,
                        amount_msat,
                        destination: String::new(),
                    })
                }
                Action::Melt => {
                    if let Some(form) = self.melt.take() {
                        let w = wallet.clone();
                        self.spawn(ctx, form.id.clone(), async move {
                            w.melt(&form.id, &form.destination).await
                        });
                    }
                }
                Action::Export(id) => self.export = Some(id),
                Action::MarkSent(id) => {
                    self.export = None;
                    self.report(wallet.mark_sent(&id));
                }
                Action::Remove(id) => self.report(wallet.remove(&id)),
                Action::Unpin(origin) => self.report(wallet.unpin_mint(&origin)),
                Action::Untrust(origin) => self.report(wallet.untrust_mint(&origin)),
                Action::Trust(address) => {
                    let w = wallet.clone();
                    let key = format!("trust:{address}");
                    if address == self.custom_mint.trim() {
                        self.custom_mint.clear();
                    }
                    self.spawn(ctx, key, async move { w.trust_mint(&address).await });
                }
                Action::StartMint => {
                    let Ok(sats) = self.mint_amount.trim().parse::<u64>() else {
                        continue;
                    };
                    let Some(msat) = sats.checked_mul(1000) else {
                        continue;
                    };
                    let address = self.mint_address.clone();
                    let w = wallet.clone();
                    self.spawn(ctx, "mint".into(), async move {
                        w.start_mint(&address, msat).await
                    });
                }
                Action::DismissMint(output) => self.report(wallet.dismiss_mint(&output)),
                Action::UseSeed(phrase) => {
                    if let Err(e) = wallet.set_seed(&phrase) {
                        self.push(false, format!("{e:#}"));
                    } else {
                        self.seed_setup = SeedSetup::default();
                        self.push(
                            true,
                            "Seed set. Trust a mint and mint or receive a note to get started."
                                .into(),
                        );
                        self.tab = Tab::Mints;
                    }
                }
                Action::RestoreSeed(phrase) => match wallet.set_seed(&phrase) {
                    Ok(()) => {
                        self.seed_setup = SeedSetup::default();
                        let w = wallet.clone();
                        self.spawn(ctx, "restore".into(), async move { w.restore().await });
                        self.tab = Tab::Seed;
                    }
                    Err(e) => self.push(false, format!("{e:#}")),
                },
                Action::Restore => {
                    let w = wallet.clone();
                    self.spawn(ctx, "restore".into(), async move { w.restore().await });
                }
                Action::Lock => {
                    self.screen = locked(None);
                    self.melt = None;
                    self.export = None;
                    self.confirm_trust = None;
                    self.qr_textures.clear();
                    self.receive_input.clear();
                    self.messages.clear();
                    self.seed_setup = SeedSetup::default();
                    self.show_seed = false;
                }
            }
        }
    }

    fn report(&mut self, result: anyhow::Result<()>) {
        if let Err(e) = result {
            self.push(false, format!("{e:#}"));
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.collect_results();
        match &self.screen {
            Screen::Locked { .. } => self.locked_ui(ui),
            Screen::Unlocked(wallet) => {
                let wallet = wallet.clone();
                let actions = if wallet.has_seed() {
                    self.wallet_ui(ui, &wallet)
                } else {
                    self.seed_setup_ui(ui)
                };
                self.apply(ui.ctx(), &wallet, actions);
            }
        }
    }
}

fn locked(error: Option<String>) -> Screen {
    Screen::Locked {
        password: String::new(),
        confirm: String::new(),
        error,
        unlocking: None,
    }
}

/// (origin, live msat, live notes) per mint holding anything, largest first.
fn mint_balances(data: &WalletData) -> Vec<(String, u64, usize)> {
    let mut balances: Vec<(String, u64, usize)> = Vec::new();
    for note in data.notes.iter().filter(|n| n.status == NoteStatus::Live) {
        let origin = note.origin();
        match balances.iter_mut().find(|(o, _, _)| *o == origin) {
            Some(entry) => {
                entry.1 += note.amount_msat;
                entry.2 += 1;
            }
            None => balances.push((origin, note.amount_msat, 1)),
        }
    }
    balances.sort_by_key(|b| std::cmp::Reverse(b.1));
    balances
}

fn largest_mint(data: &WalletData) -> String {
    mint_balances(data)
        .into_iter()
        .next()
        .map(|(origin, _, _)| origin)
        .unwrap_or_default()
}

/// Which mint's notes to spend: only one mint's notes can go into a split,
/// merge or transfer together.
fn mint_picker(
    ui: &mut egui::Ui,
    id: &str,
    origin: &mut String,
    balances: &[(String, u64, usize)],
) {
    let label = |o: &str, total: u64| {
        format!(
            "{}  ({} sats)",
            lnurlcash_core::server_of(o),
            msat_to_sats(total)
        )
    };
    let selected = balances
        .iter()
        .find(|(o, _, _)| o == origin)
        .map(|(o, total, _)| label(o, *total))
        .unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("From");
        egui::ComboBox::from_id_salt(id)
            .selected_text(selected)
            .width(280.0)
            .show_ui(ui, |ui| {
                for (o, total, _) in balances {
                    ui.selectable_value(origin, o.clone(), label(o, *total));
                }
            });
    });
}

/// The 12 words, numbered, in three columns.
fn seed_words(ui: &mut egui::Ui, phrase: &str) {
    egui::Grid::new(("seed-words", phrase.len()))
        .num_columns(3)
        .spacing([24.0, 6.0])
        .show(ui, |ui| {
            for (i, word) in phrase.split_whitespace().enumerate() {
                ui.monospace(format!("{:>2}. {word}", i + 1));
                if i % 3 == 2 {
                    ui.end_row();
                }
            }
        });
}

fn status_color(status: NoteStatus) -> Color32 {
    match status {
        NoteStatus::Live => Color32::from_rgb(80, 190, 110),
        NoteStatus::Melting => Color32::from_rgb(220, 190, 60),
        NoteStatus::Uncertain => Color32::from_rgb(230, 120, 40),
        NoteStatus::Sent => Color32::from_rgb(90, 150, 230),
        NoteStatus::Spent => Color32::GRAY,
    }
}

fn short(key: &str) -> String {
    if key.len() > 20 {
        format!("{}…{}", &key[..10], &key[key.len() - 8..])
    } else {
        key.to_string()
    }
}

fn format_time(unix: u64) -> String {
    // UTC, no date crate needed: days since epoch -> civil date (Hinnant)
    let (days, secs) = ((unix / 86_400) as i64, unix % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year}-{month:02}-{day:02} {:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60
    )
}

fn qr_image(data: &str) -> egui::ColorImage {
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M)
        .or_else(|_| qrcode::QrCode::new(data.as_bytes()))
        .expect("a note fits in a QR code");
    let width = code.width();
    let quiet = 4;
    let size = width + 2 * quiet;
    let colors = code.to_colors();
    let mut pixels = vec![Color32::WHITE; size * size];
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                pixels[(y + quiet) * size + x + quiet] = Color32::BLACK;
            }
        }
    }
    egui::ColorImage::new([size, size], pixels)
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_utc_times() {
        assert_eq!(super::format_time(0), "1970-01-01 00:00");
        assert_eq!(super::format_time(1_790_000_000), "2026-09-21 14:13");
    }
}
