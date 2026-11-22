//! The worker side: one request per process, sandboxed before any
//! archive byte is read.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zip67_core::extract::{Answer, Prompt};
use zip67_core::update::{Changes, UpdateOptions};
use zip67_core::{Entry, Error, OpenOptions, Password, Progress, open};

use crate::protocol::{Control, Event, Failure, HashResult, Job, Question, Reply, Request};
use crate::sandbox::{Access2, apply};

type Out = Arc<Mutex<io::Stdout>>;

fn send(out: &Out, ev: &Event) {
    if let (Ok(line), Ok(mut o)) = (serde_json::to_string(ev), out.lock()) {
        let _ = writeln!(o, "{line}");
        let _ = o.flush();
    }
}

fn parts_of(archive: &Path) -> Vec<PathBuf> {
    // All parts of a split archive must be readable inside the sandbox.
    zip67_core::source::volume_parts(archive).unwrap_or_else(|| vec![archive.to_path_buf()])
}

fn parent(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Files and folders a job needs, nothing more. With a staging folder,
/// archives are written only there (never next to the target).
pub fn access_for_job(job: &Job) -> Access2 {
    let mut a = access_for(&job.request);
    if let Some(stage) = &job.stage
        && matches!(
            job.request,
            Request::Create { .. } | Request::AddFiles { .. } | Request::Update { .. }
        )
    {
        a.write = vec![stage.clone()];
    }
    a
}

/// Files and folders a request needs, nothing more.
pub fn access_for(req: &Request) -> Access2 {
    match req {
        Request::List { archive, .. } | Request::Test { archive, .. } => Access2 {
            read: parts_of(archive),
            write: vec![],
        },
        Request::Extract { archive, dest, .. } => {
            let _ = std::fs::create_dir_all(dest);
            Access2 {
                read: parts_of(archive),
                write: vec![dest.clone()],
            }
        }
        Request::Create { output, inputs, .. } => Access2 {
            read: inputs.clone(),
            write: vec![parent(output)],
        },
        Request::AddFiles {
            archive, inputs, ..
        } => {
            let mut read = inputs.clone();
            read.push(archive.clone());
            Access2 {
                read,
                write: vec![parent(archive)],
            }
        }
        Request::Update {
            archive, changes, ..
        } => {
            let mut read: Vec<PathBuf> = changes.add.iter().map(|(p, _)| p.clone()).collect();
            read.push(archive.clone());
            Access2 {
                read,
                write: vec![parent(archive)],
            }
        }
        Request::Hash { paths, .. } => Access2 {
            read: paths.clone(),
            write: vec![],
        },
        Request::Benchmark { .. } => Access2::default(),
    }
}

struct WorkerPrompt {
    out: Out,
    answers: Receiver<Answer>,
}

impl Prompt for WorkerPrompt {
    fn overwrite(
        &mut self,
        path: &str,
        existing_size: u64,
        existing_mtime: Option<i64>,
        entry: &Entry,
    ) -> Answer {
        send(
            &self.out,
            &Event::Ask(Question {
                path: path.to_string(),
                existing_size,
                existing_mtime,
                new_size: entry.size,
                new_mtime: entry.mtime,
            }),
        );
        self.answers.recv().unwrap_or(Answer::Cancel)
    }
}

fn pw(p: &Option<String>) -> Option<Password> {
    p.clone().filter(|s| !s.is_empty()).map(Password::new)
}

/// Runs a job: like [`execute`], writing archives into the staging folder.
pub fn execute_job(
    job: Job,
    progress: &Progress,
    prompt: &mut dyn Prompt,
) -> zip67_core::Result<Reply> {
    let Some(stage) = job.stage else {
        return execute(job.request, progress, prompt);
    };
    match job.request {
        Request::Create {
            output,
            inputs,
            spec,
        } => {
            let opts = zip67_core::create::CreateOptions {
                out_dir: Some(stage),
                ..spec.to_options()?
            };
            Ok(Reply::Created(zip67_core::create::create(
                &output, &inputs, &opts, progress,
            )?))
        }
        Request::AddFiles {
            archive,
            inputs,
            arc_dir,
            spec,
        } => {
            let opts = zip67_core::create::CreateOptions {
                out_dir: Some(stage),
                ..spec.to_options()?
            };
            Ok(Reply::Created(zip67_core::update::add_files(
                &archive, &inputs, &arc_dir, &opts, progress,
            )?))
        }
        Request::Update {
            archive,
            password,
            changes,
            level,
            threads,
        } => {
            let ch = Changes {
                add: changes.add,
                delete: changes.delete,
                rename: changes.rename,
                new_dirs: changes.new_dirs,
            };
            let opts = UpdateOptions {
                password: pw(&password),
                level,
                threads: if threads == 0 {
                    zip67_core::util::default_threads()
                } else {
                    threads
                },
                out_dir: Some(stage),
                ..Default::default()
            };
            Ok(Reply::Created(zip67_core::update::modify(
                &archive, &ch, &opts, progress,
            )?))
        }
        other => execute(other, progress, prompt),
    }
}

pub fn execute(
    req: Request,
    progress: &Progress,
    prompt: &mut dyn Prompt,
) -> zip67_core::Result<Reply> {
    match req {
        Request::List { archive, password } => {
            let r = open(
                &archive,
                &OpenOptions {
                    password: pw(&password),
                    ..Default::default()
                },
            )?;
            Ok(Reply::Listing {
                archive_type: r.archive_type().id(),
                entries: r.entries().to_vec(),
                info: r.info(),
            })
        }
        Request::Extract {
            archive,
            password,
            dest,
            selection,
            options,
        } => {
            let mut r = open(
                &archive,
                &OpenOptions {
                    password: pw(&password),
                    limits: options.limits.clone(),
                    ..Default::default()
                },
            )?;
            let rep = zip67_core::extract::extract_to(
                r.as_mut(),
                &dest,
                &selection,
                &options,
                Some(prompt),
                progress,
            )?;
            Ok(Reply::Extracted(rep))
        }
        Request::Test {
            archive,
            password,
            selection,
        } => {
            let mut r = open(
                &archive,
                &OpenOptions {
                    password: pw(&password),
                    ..Default::default()
                },
            )?;
            Ok(Reply::Tested(zip67_core::extract::test(
                r.as_mut(),
                &selection,
                progress,
            )?))
        }
        Request::Create {
            output,
            inputs,
            spec,
        } => Ok(Reply::Created(zip67_core::create::create(
            &output,
            &inputs,
            &spec.to_options()?,
            progress,
        )?)),
        Request::AddFiles {
            archive,
            inputs,
            arc_dir,
            spec,
        } => Ok(Reply::Created(zip67_core::update::add_files(
            &archive,
            &inputs,
            &arc_dir,
            &spec.to_options()?,
            progress,
        )?)),
        Request::Update {
            archive,
            password,
            changes,
            level,
            threads,
        } => {
            let ch = Changes {
                add: changes.add,
                delete: changes.delete,
                rename: changes.rename,
                new_dirs: changes.new_dirs,
            };
            let opts = UpdateOptions {
                password: pw(&password),
                level,
                threads: if threads == 0 {
                    zip67_core::util::default_threads()
                } else {
                    threads
                },
                ..Default::default()
            };
            Ok(Reply::Created(zip67_core::update::modify(
                &archive, &ch, &opts, progress,
            )?))
        }
        Request::Hash { paths, kinds } => {
            let total: u64 = paths
                .iter()
                .filter_map(|p| std::fs::metadata(p).ok())
                .map(|m| m.len())
                .sum();
            progress.set_total(total);
            let mut out = Vec::new();
            for p in paths {
                progress.set_current(&p.to_string_lossy());
                match zip67_core::hash::hash_file(&p, &kinds, progress) {
                    Ok((size, values)) => out.push(HashResult {
                        path: p,
                        size,
                        values,
                        error: None,
                    }),
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(e) => out.push(HashResult {
                        path: p,
                        size: 0,
                        values: vec![],
                        error: Some(e.to_string()),
                    }),
                }
            }
            Ok(Reply::Hashes(out))
        }
        Request::Benchmark {
            seconds,
            threads,
            dict_size: _,
        } => {
            let size = (seconds.clamp(1, 60) as usize) * (8 << 20);
            Ok(Reply::Benchmark(zip67_core::bench::run(
                size,
                threads.max(1),
                progress,
            )?))
        }
    }
}

/// Runs the worker protocol on stdin/stdout. Returns the exit code.
pub fn run() -> i32 {
    let stdin = io::stdin();
    let mut first = String::new();
    if stdin.lock().read_line(&mut first).is_err() || first.len() > 64 << 20 {
        return 2;
    }
    let job: Job = match serde_json::from_str::<Job>(first.trim()).or_else(|_| {
        serde_json::from_str::<Request>(first.trim()).map(|request| Job {
            request,
            stage: None,
        })
    }) {
        Ok(j) => j,
        Err(e) => {
            let out: Out = Arc::new(Mutex::new(io::stdout()));
            send(
                &out,
                &Event::Failed(Failure {
                    kind: crate::protocol::FailKind::Invalid,
                    message: format!("bad request: {e}"),
                }),
            );
            return 2;
        }
    };
    // Lock down before anything else happens (and before any thread starts).
    let status = apply(&access_for_job(&job));
    let out: Out = Arc::new(Mutex::new(io::stdout()));
    send(
        &out,
        &Event::Hello {
            version: zip67_core::VERSION.into(),
            sandbox: status,
        },
    );

    let progress = Progress::new();
    let (atx, arx) = mpsc::channel();
    {
        let progress = progress.clone();
        std::thread::spawn(move || {
            for line in io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                match serde_json::from_str::<Control>(line.trim()) {
                    Ok(Control::Cancel) => progress.cancel(),
                    Ok(Control::Pause) => progress.pause(),
                    Ok(Control::Resume) => progress.resume(),
                    Ok(Control::Answer(a)) => {
                        let _ = atx.send(a);
                    }
                    Err(_) => {}
                }
            }
            // Client went away: stop.
            progress.cancel();
        });
    }
    let done = Arc::new(AtomicBool::new(false));
    let ticker = {
        let (progress, out, done) = (progress.clone(), out.clone(), done.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                send(&out, &Event::Progress(progress.snapshot()));
                std::thread::sleep(Duration::from_millis(150));
            }
        })
    };
    let mut prompt = WorkerPrompt {
        out: out.clone(),
        answers: arx,
    };
    let result = execute_job(job, &progress, &mut prompt);
    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    send(&out, &Event::Progress(progress.snapshot()));
    match result {
        Ok(reply) => {
            send(&out, &Event::Done(reply));
            0
        }
        Err(e) => {
            send(&out, &Event::Failed(Failure::from(&e)));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CreateSpec;

    #[test]
    fn staged_jobs_write_only_to_the_stage() {
        let req = Request::Create {
            output: "/home/u/out.7z".into(),
            inputs: vec!["/home/u/doc".into()],
            spec: CreateSpec::default(),
        };
        let a = access_for_job(&Job {
            request: req.clone(),
            stage: Some("/home/u/.67zip-x".into()),
        });
        assert_eq!(a.write, vec![PathBuf::from("/home/u/.67zip-x")]);
        assert_eq!(a.read, vec![PathBuf::from("/home/u/doc")]);
        let a = access_for_job(&Job {
            request: req,
            stage: None,
        });
        assert_eq!(a.write, vec![PathBuf::from("/home/u")]);
    }
}
