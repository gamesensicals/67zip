//! Debug helper: opens an archive, tests it, prints progress every second.
use std::time::Duration;
use zip67_core::{Limits, OpenOptions, Progress, open};
fn main() {
    let path = std::env::args().nth(1).expect("file");
    let p = Progress::new();
    let p2 = p.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let s = p2.snapshot();
            eprintln!("done={} total={} current={}", s.done, s.total, s.current);
        }
    });
    let limits = Limits {
        max_total_size: 64 << 20,
        ..Default::default()
    };
    let password = std::env::args().nth(2).map(zip67_core::Password::new);
    let mut r = match open(
        path.as_ref(),
        &OpenOptions {
            limits,
            threads: 1,
            password,
            ..Default::default()
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("open: {e}");
            return;
        }
    };
    for e in r.entries() {
        println!(
            "{} size={} block={:?} method={:?}",
            e.path, e.size, e.block, e.method
        );
    }
    let res = zip67_core::extract::test(r.as_mut(), &zip67_core::extract::Selection::All, &p);
    println!("result: {:?}", res.map(|r| r.errors));
}
