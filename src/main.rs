mod app;
mod nfc;
mod ui;

fn main() -> gtk::glib::ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    app::run()
}
