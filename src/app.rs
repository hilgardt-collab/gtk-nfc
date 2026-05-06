use adw::prelude::*;
use gtk::glib;

pub const APP_ID: &str = "com.hilgardt.gtknfc";

pub fn run() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        let window = crate::ui::window::build(app);
        window.present();
    });
    app.run()
}
