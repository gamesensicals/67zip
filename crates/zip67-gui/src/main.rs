//! 67zip: the graphical archive manager.

#![forbid(unsafe_code)]
#![windows_subsystem = "windows"]

mod app;
mod forms;
mod icons;
mod listing;
mod platform;
mod settings;
mod style;
mod update;
mod view;

fn main() -> iced::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--worker") {
        std::process::exit(zip67_worker::server::run());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: 67zip [folder or archive]\n       67zip --add FILES...\n       67zip --add-with-password FILES...\n       67zip --extract ARCHIVE | --extract-here ARCHIVE | --extract-to-folder ARCHIVE");
        return Ok(());
    }
    let launch = app::Launch::from_args(&args);
    let icon = iced::window::icon::from_file_data(include_bytes!("../resources/67zip-256.png"), None).ok();
    let result = iced::application(move || app::App::new(launch.clone()), app::App::update, app::App::view)
        .title(app::App::title)
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .scale_factor(app::App::scale)
        .font(include_bytes!("../resources/fonts/Inter-Regular.otf").as_slice())
        .font(include_bytes!("../resources/fonts/Inter-Medium.otf").as_slice())
        .font(include_bytes!("../resources/fonts/Inter-SemiBold.otf").as_slice())
        .default_font(view::INTER)
        .window(iced::window::Settings {
            size: iced::Size::new(1180.0, 740.0),
            min_size: Some(iced::Size::new(720.0, 420.0)),
            icon,
            platform_specific: iced::window::settings::PlatformSpecific { application_id: "io.github.gamesensicals.SixtySevenZip".into(), ..Default::default() },
            ..Default::default()
        })
        .antialiasing(true)
        .run();
    // Decrypted temporary copies do not outlive the app.
    platform::wipe_own_temp();
    result
}
