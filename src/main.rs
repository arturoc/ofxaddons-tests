extern crate json;
extern crate time;
extern crate clap;
extern crate regex;
extern crate walkdir;
extern crate reqwest;
#[macro_use] extern crate log;

use reqwest::{header, Url};

use clap::{Arg, App};

use regex::Regex;

use walkdir::WalkDir;

use std::io::{Read, Write, Result as IoResult};
use std::io::BufReader;
use std::io::BufRead;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::thread;
use std::collections::{HashMap, HashSet};
use std::process::{Command, Output};
use std::error::Error;

// mod simple_http;

static OFXADDONS_LOGIN: &'static str = "ofxaddons-tests";

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq)]
struct Owner{
    login: String
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq)]
struct Repository {
    owner: Owner,
    name: String,
    html_url: String,
    url: String,
    whitelisted: bool,
}

impl Repository{
    fn path(&self) -> PathBuf {
        Path::new("data").join(&self.name).to_owned()
    }
}

fn git_clone<P: AsRef<Path>>(repo: &str, path: P) -> IoResult<Output>{
    info!("Cloning {} to {}", repo, path.as_ref().display());
    Command::new("git")
            .arg("clone")
            .arg(repo)
            .arg(path.as_ref())
            .output()
}

fn git_shallow_clone<P: AsRef<Path>>(repo: &str, path: P) -> IoResult<Output>{
    info!("Shallow cloning {} to {}", repo, path.as_ref().display());
    let mut command = Command::new("git");
    command.arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--branch")
            .arg("master")
            .arg(repo)
            .arg(path.as_ref())
            .current_dir("data");
    command.output()
}

fn git_add<P: AsRef<Path>>(repo: P, args: &str) -> IoResult<Output>{
    Command::new("git")
            .arg("add")
            .arg(args)
            .current_dir(repo)
            .output()
}

fn git_commit<P: AsRef<Path>>(repo: P, message: &str) -> IoResult<Output>{
    Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg(message)
            .current_dir(repo)
            .output()
}

fn git_push<P: AsRef<Path>>(repo: P, url: &str) -> IoResult<Output>{
    Command::new("git")
            .arg("push")
            .arg(url)
            .arg("master")
            .current_dir(repo)
            .output()
}

fn test_correct_addon<P: AsRef<Path>>(repo_path: P, addon_name: &str) -> Result<String, ()>{
    if !repo_path.as_ref().exists(){
        return Err(());
    }
    let src_path = repo_path.as_ref().join("src");
    let libs_path = repo_path.as_ref().join("libs");
    let has_src = src_path.exists();
    let has_src_header = src_path.join(&[addon_name, ".h"].concat()).exists();
    let has_libs = libs_path.exists();
    let has_correct_lib = has_libs && {
        let libs = libs_path.read_dir().unwrap().filter(|lib| lib.as_ref().unwrap().file_type().unwrap().is_dir());
        let num_libs = libs.count();
        num_libs > 0 && {
            let mut libs = libs_path.read_dir().unwrap().filter(|lib| lib.as_ref().unwrap().file_type().unwrap().is_dir());
            let first_lib = libs.next().unwrap().unwrap().path();
            let lib_has_src = first_lib.join("src").exists();
            let lib_has_include = first_lib.join("include").exists();
            let first_lib_bin = first_lib.join("lib");
            let lib_has_supported_platform =
                first_lib_bin.join("osx").exists() ||
                first_lib_bin.join("android").exists() ||
                first_lib_bin.join("linuxarmv6l").exists() ||
                first_lib_bin.join("linuxarmv7l").exists() ||
                first_lib_bin.join("linux64").exists() ||
                first_lib_bin.join("vs").exists() ||
                first_lib_bin.join("msys2").exists() ||
                first_lib_bin.join("ios").exists();

            lib_has_src || (lib_has_include && lib_has_supported_platform)
        }
    };

    let of_headers_file = BufReader::new(File::open("config/of_headers").unwrap());
    let of_headers = of_headers_file.lines().map(|line| line.unwrap()).collect::<Vec<_>>();
    let of_headers_regex = of_headers.iter()
        .map(|header| Regex::new(&format!("#include\\s*\"{}\"",header)).unwrap())
        .collect::<Vec<_>>();

    let includes_of_source = has_src && WalkDir::new(&src_path).into_iter().filter_map(|e| e.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry|
            entry.path().extension().is_some() && {
                let ext = entry.path().extension().unwrap();
                ext == "h" ||
                ext == "hpp"||
                ext == "c"||
                ext == "cpp"||
                ext == "h"||
                ext == "mm"
            })
        .any(|entry|{
            let mut source_file = File::open(entry.path()).unwrap();
            let mut source = String::new();
            source_file.read_to_string(&mut source).is_ok() &&
                of_headers_regex.iter().any(|header| header.is_match(&source))
            //of_headers.iter().any(|header| source.contains(&format!("#include \"{}\"", header)))

        });

    let has_c_source = has_src && WalkDir::new(&src_path).into_iter().filter_map(|e| e.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.path().extension().is_some())
        .filter(|entry|
            entry.path().extension().unwrap() == "h" ||
            entry.path().extension().unwrap() == "hpp"||
            entry.path().extension().unwrap() == "c"||
            entry.path().extension().unwrap() == "cpp"||
            entry.path().extension().unwrap() == "h"||
            entry.path().extension().unwrap() == "mm")
        .count() > 0;

    let readme_contains_of = repo_path.as_ref().read_dir().unwrap()
        .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_file())
        .filter(|entry| {
            let path = entry.as_ref().unwrap().path();
            let filename = path.as_path().file_name();
            filename.is_some() && filename.unwrap().to_str().unwrap().to_lowercase().starts_with("readme")
        })
        .any(|readme| {
            let path = readme.as_ref().unwrap().path();
            let mut file = File::open(path).unwrap();
            let mut readme_str = String::new();
            file.read_to_string(&mut readme_str).is_ok() &&
                readme_str.to_lowercase().contains("openframeworks")
        });

    let has_addon_config = repo_path.as_ref().join(Path::new("addon_config.mk")).exists();

    let reasons = [
        if has_src_header {
            Some(format!("has a src/{}.h file", addon_name))
        }else{
            None
        },

        if has_c_source {
            Some("has c, c++ or objc source in an src folder".to_string())
        }else{
            None
        },

        if includes_of_source{
            Some("any of the present c or c++ source files includes an openFrameworks header".to_string())
        }else{
            None
        },

        if has_correct_lib{
            Some("has a libs folder that is organized using the OF addons standard".to_string())
        }else{
            None
        },

        if has_c_source && readme_contains_of{
            Some("has a readme file that mentions openframeworks".to_string())
        }else{
            None
        },

        if has_addon_config {
            Some("has an addon_config.mk file in the root folder".to_string())
        }else{
            None
        }
    ];

    let reasons = reasons.iter().filter_map(|reason| reason.clone()).collect::<Vec<_>>();

    if has_src_header || includes_of_source || has_correct_lib || (has_c_source && readme_contains_of) || has_addon_config{
        Ok(reasons[0..reasons.len()-1].join(", ") + " and " + &reasons.last().unwrap())
    }else{
        Err(())
    }
}

fn build_repos_index(oauth_token: &str, owner: Option<&str>) -> Vec<Repository>{
    let url = if let Some(owner) = owner {
        "https://api.github.com/search/repositories?q=ofx+in:name+user:".to_string() + owner + "&per_page=100"
    }else{
        "https://api.github.com/search/repositories?q=ofx+in:name&per_page=100".to_string()
    };

    let mut repos = vec![];

    let mut blacklist_file = File::open("config/blacklist_re").unwrap();
    let mut blacklist_str = String::new();
    blacklist_file.read_to_string(&mut blacklist_str).unwrap();
    let mut blacklist = blacklist_str.lines()
                        .filter(|item| !item.trim().is_empty())
                        .map(|item| Regex::new(item).unwrap())
                        .collect::<Vec<_>>();

    let mut blacklist_file = File::open("config/blacklist").unwrap();
    let mut blacklist_str = String::new();
    blacklist_file.read_to_string(&mut blacklist_str).unwrap();
    blacklist.extend(blacklist_str.lines()
                        .filter(|item| !item.trim().is_empty())
                        .map(|item| format!("^{}$", item))
                        .map(|item| Regex::new(&item).unwrap()));


    let mut whitelist_file = File::open("config/whitelist").unwrap();
    let mut whitelist_str = String::new();
    whitelist_file.read_to_string(&mut whitelist_str).unwrap();
    let whitelist = whitelist_str.lines()
                        .filter(|item| !item.trim().is_empty())
                        .collect::<Vec<_>>();

    info!("Next: {}", url);
    let mut url = Url::parse(&url).unwrap();
    let mut default_headers = header::HeaderMap::new();
    default_headers.append(header::USER_AGENT, header::HeaderValue::from_static("ofxaddons"));
    default_headers.append(header::AUTHORIZATION, header::HeaderValue::from_str(oauth_token).unwrap());
    let http = reqwest::ClientBuilder::new()
        .default_headers(default_headers)
        .build()
        .unwrap();
    loop{
        let mut res = http.get(url).send().unwrap();
        let parsed = json::parse(&res.text().unwrap()).unwrap();
        let new_repos = parsed["items"].members()
            .filter(|&repo| repo["name"].to_string().starts_with("ofx"))
            .filter(|&repo| !blacklist.iter().any(|re| re.is_match(&repo["name"].to_string())))
            .filter(|&repo| {
                let first_letter = &repo["name"].to_string().chars().skip(3).next().unwrap();
                first_letter.to_uppercase().next().unwrap() == *first_letter
            })
            .map(|repo| Repository{
                name: repo["name"].to_string(),
                html_url: repo["html_url"].to_string(),
                url: repo["url"].to_string(),
                owner: Owner{
                    login: repo["owner"]["login"].to_string(),
                },
                whitelisted: whitelist.iter().any(|item| item == &repo["name"].to_string())
            });

        repos.extend(new_repos);

        match res.headers().get("Link"){
            Some(next_link) => if next_link.len() > 0{
                let ratelimit = res.headers()["X-RateLimit-Limit"].to_str().unwrap();//String::from_utf8(res.headers().get("X-RateLimit-Limit").unwrap().iter().next().unwrap().to_vec()).unwrap();
                let remaining = res.headers()["X-RateLimit-Remaining"].to_str().unwrap();
                let reset = res.headers()["X-RateLimit-Reset"].to_str().unwrap();
                let reset = time::Timespec{
                    sec: reset.parse::<i64>().unwrap() + 10,
                    nsec: 0
                };

                let link = res.headers()["Link"].to_str().unwrap();
                let rels: HashMap<_,_> = link.split(",")
                    .map(|rel|{
                        let mut link_rel = rel.split(";");
                        let link = link_rel.next().unwrap().trim();
                        let rel = link_rel.next().unwrap().trim();
                        let rel = rel.split("\"").skip(1).next().unwrap().to_string();
                        let url = link[1..link.len()-1].to_string();
                        (rel, url)
                    })
                    .collect();

                match rels.get("next"){
                    Some(next) => {
                        url = next.parse().unwrap();
                        if remaining.parse::<u32>().unwrap()==0 {
                            let pause = reset - time::now().to_timespec();
                            info!("pausing for {}s", pause.num_seconds());
                            thread::sleep(pause.to_std().unwrap());
                            // http = SimpleHttp::new();
                        }
                    },
                    None => break
                }

                info!("{}/{} Next: {}", remaining, ratelimit, url);
            }else{
                break;
            },
            None => break
        }
    }

    repos
}

fn add_test_files(repo: &Repository, repo_url: &str, reason: &str) -> Result<String, String>{
    let travis = repo.path().join(".travis.yml");
    let appveyor = repo.path().join(".appveyor.yml");
    let commit_title = "Adding travis and appveyor cotinuous integration tests";
    let commit_msg = format!(include_str!("pr_message.txt"), owner=repo.owner.login, repo=repo.name, reason=reason);
    fs::copy("data/ofxAddonTemplate/.travis.yml", travis)
        .expect("Couldn't copy .travis.yml");
    fs::copy("data/ofxAddonTemplate/.appveyor.yml", appveyor)
        .expect("Couldn't copy .appveyor.yml");
    let out = git_add(&repo.path(), ".travis.yml").expect("git add .travis.yml failed");
    if !out.status.success(){
        return Err(format!("git add .travis.yml failed"));
    }
    let out = git_add(&repo.path(), ".appveyor.yml").expect("git add .appveyor.yml failed");
    if !out.status.success(){
        return Err(format!("git add .appveyor.yml failed"));
    }
    let message = commit_title.to_string() + "\n\n" + &commit_msg;
    let out = git_commit(&repo.path(), &message).expect("git commit test files failed");
    if !out.status.success(){
        return Err(format!("git commit test files failed"));
    }
    let out = git_push(&repo.path(), &repo_url).expect("git push failed");
    if !out.status.success(){
        return Err(format!("git push failed"));
    }

    Ok(commit_msg)
}

fn send_pr(http: &mut reqwest::Client, oauth_token: &str, repo: &Repository) -> Result<(),String>{
    let commit_title = "Adding travis and appveyor cotinuous integration tests";

    let fork_url = "https://api.github.com/repos/".to_string() + &repo.owner.login + "/" + &repo.name + "/forks";
    let fork_url = Url::parse(&fork_url).unwrap();
    let mut res = http.post(fork_url)
        .bearer_auth(oauth_token)
        .send()
        .map_err(|err| err.description().to_string())?;
    if !res.status().is_success(){
        return Err(format!("Error forking: {} {:?}", res.status(), res.text()));
    }

    let repo_check_url = "https://api.github.com/repos/".to_string() + OFXADDONS_LOGIN + "/" + &repo.name;
    loop{
        thread::sleep(std::time::Duration::from_secs(10));
        let repo_check_url = Url::parse(&repo_check_url).unwrap();
        let res = http.get(repo_check_url)
                .bearer_auth(oauth_token)
                .send();
        if let Ok(res) = res {
            if res.status().is_success(){
                break;
            }else{
                info!("Fork hasn't finished yet, waiting 10s");
            }
        }
    }

    let repo_url = "https://".to_string() + oauth_token + "@github.com/" + OFXADDONS_LOGIN + "/" + &repo.name;

    try!(git_clone(&repo_url, repo.path()).map_err(|err| err.description().to_string()));

    let test_addon_result = test_correct_addon(repo.path(), &repo.name);
    let pr_res = if repo.whitelisted || test_addon_result.is_ok(){
        let travis = repo.path().join(".travis.yml");
        let appveyor = repo.path().join(".appveyor.yml");

        if !Path::new(&travis).exists() && !Path::new(&appveyor).exists(){
            let reason = if repo.whitelisted {
                "Addon is included in the whitelist"
            }else{
                test_addon_result.as_ref().unwrap()
            };

            match add_test_files(&repo, &repo_url, reason){
                Ok(commit_msg) => {
                    let pr_url = "https://api.github.com/repos/".to_string() + &repo.owner.login + "/" + &repo.name + "/pulls";
                    let pr_url = Url::parse(&pr_url).unwrap();
                    let body = format!("{{
                        \"title\": \"{}\",
                        \"body\": \"{}\",
                        \"base\": \"master\",
                        \"head\": \"{}:master\"
                    }}", commit_title, commit_msg.replace("\n","\\n"), OFXADDONS_LOGIN);
                    let mut res = try!(http.post(pr_url)
                        .bearer_auth(oauth_token)
                        .body(body)
                        .send()
                        .map_err(|err| err.description().to_string()));

                    if res.status().is_success() {
                        Ok(())
                    }else{
                        Err(format!("Error creating PR: {} {:?}", res.status(), res.text()))
                    }
                }

                Err(err) => Err(err)
            }
        }else{
            Err(format!("{} already has test config, skipping", &repo.name))
        }
    }else{
        Err(format!("{}:{} doesn't look like a correct addon.", repo.owner.login, repo.name))
    };


    let rm_url = "https://api.github.com/repos/".to_string() + OFXADDONS_LOGIN + "/" + &repo.name;
    let rm_url = Url::parse(&rm_url).unwrap();
    let mut res = http.delete(rm_url)
        .bearer_auth(oauth_token)
        .send()
        .unwrap();
    let pr_res = if res.status().is_success() {
        pr_res
    }else{
        Err(format!("Error removing fork {}:{} {} {:?}", repo.owner.login, repo.name, res.status(), res.text()))
    };

    fs::remove_dir_all(&repo.path()).expect("Couldn't remove repository directory");

    pr_res
}

fn send_test_prs(repos: &Vec<Repository>, oauth_token: &str){
    let prs_sent_path = Path::new("config").join("prs_sent");
    let mut prs_sent = String::new();
    let prs_sent = match File::open(&prs_sent_path){
        Ok(mut file) => {
            file.read_to_string(&mut prs_sent).unwrap();
            prs_sent.lines().map(|line| line.to_string()).collect::<HashSet<String>>()
        }
        Err(_) => HashSet::new(),
    };

    git_clone("https://github.com/openframeworks/ofxAddonTemplate", "data/ofxAddonTemplate")
        .expect("Couldn't clone ofxAddonTemplate");
    let ts = time::now();
    let mut errors = File::create(Path::new("data").join(format!("pr_errors{}.out", timestamp(&ts)))).unwrap();
    let mut correct = File::create(Path::new("data").join(format!("pr_correct{}.out", timestamp(&ts)))).unwrap();

    let mut default_headers = header::HeaderMap::new();
    default_headers.append(header::USER_AGENT, header::HeaderValue::from_static("ofxaddons"));
    default_headers.append(header::AUTHORIZATION, header::HeaderValue::from_str(oauth_token).unwrap());
    let mut http = reqwest::ClientBuilder::new()
        .default_headers(default_headers)
        .build()
        .unwrap();
    let mut new_prs_sent = HashSet::new();
    for repo in repos.iter().filter(|&repo| !prs_sent.contains(&(repo.owner.login.clone() + ":" + &repo.name))){
        let pr_res = send_pr(&mut http, oauth_token, &repo);
        if pr_res.is_ok(){
            new_prs_sent.insert(repo.owner.login.clone() + ":" + &repo.name);
            correct.write(&format!("PR sent correctly to: {}:{}", repo.owner.login, repo.name).into_bytes()).unwrap();
        }else{
            errors.write(&pr_res.unwrap_err().into_bytes()).unwrap();
        }
    }

    fs::remove_dir_all("data/ofxAddonTemplate").expect("Couldn't remove repository directory");

    new_prs_sent.extend(prs_sent.into_iter());
    let mut prs_sent_file = File::create(&prs_sent_path).unwrap();
    for pr in new_prs_sent{
        prs_sent_file.write(&(pr + "\n").into_bytes()).unwrap();
    }
}

fn send_one_test_pr(repo: &Repository, oauth_token: &str){
    let prs_sent_path = Path::new("config").join("prs_sent");
    if checkaddons(&vec![repo.clone()])[0]{
        info!("Correct addon detected");
        let mut prs_sent = String::new();
        let mut prs_sent = match File::open(&prs_sent_path){
            Ok(mut file) => {
                file.read_to_string(&mut prs_sent).unwrap();
                prs_sent.lines().map(|line| line.to_string()).collect::<HashSet<String>>()
            }
            Err(_) => HashSet::new(),
        };
        let slug = repo.owner.login.clone() + ":" + &repo.name;
        if !prs_sent.contains(&slug){
            info!("PR not sent yet, sending");
            git_clone("https://github.com/openframeworks/ofxAddonTemplate", "data/ofxAddonTemplate")
                .expect("Couldn't clone ofxAddonTemplate");
            let mut default_headers = header::HeaderMap::new();
            default_headers.append(header::USER_AGENT, header::HeaderValue::from_static("ofxaddons"));
            default_headers.append(header::AUTHORIZATION, header::HeaderValue::from_str(oauth_token).unwrap());
            let mut http = reqwest::ClientBuilder::new()
                .default_headers(default_headers)
                .build()
                .unwrap();
            let pr_sent = send_pr(&mut http, oauth_token, repo);

            fs::remove_dir_all("data/ofxAddonTemplate")
                .expect("Couldn't remove repository directory");
            pr_sent.unwrap();
            info!("PR sent correctly");

            prs_sent.insert(slug);
            let mut prs_sent_file = File::create(&prs_sent_path).unwrap();
            for pr in prs_sent{
                prs_sent_file.write(&(pr + "\n").into_bytes()).unwrap();
            }
        }else{
            panic!("PR already sent");
        }
    }
}

fn timestamp(ts: &time::Tm) -> String{
    format!("{}{:02}{:02}{:02}{:02}{:02}", 1900 + ts.tm_year, ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec)
}

fn checkaddons(repos: &Vec<Repository>) -> Vec<bool>{
    //let client = Client::new();
    let ts = time::now();
    let mut failed = File::create(Path::new("data").join(format!("failed_addons{}.out", timestamp(&ts)))).unwrap();
    let mut correct = File::create(Path::new("data").join(format!("correct_addons{}.out", timestamp(&ts)))).unwrap();
    repos.iter().map(|repo|{
        let slug = format!("{}:{}", repo.owner.login, repo.name);
        let repo_path = Path::new("data").join(&slug);
        let test_addon_result = if repo.whitelisted {
            Ok("Addon is included in the whitelist".to_string())
        }else if git_shallow_clone(&repo.html_url, &slug).expect("Failed cloning").status.success(){;
            test_correct_addon(&repo_path, &repo.name)
        }else{
            error!("{} failed to download.", slug);
            failed.write(&slug.into_bytes()).unwrap();
            failed.write(&"\n".to_string().into_bytes()).unwrap();
            return false;
        };

        if test_addon_result.is_ok(){
            if !repo.whitelisted{
                fs::remove_dir_all(&repo_path).expect("Couldn't remove repository directory");
            }
            correct.write(&slug.into_bytes()).unwrap();
            correct.write(&format!(" {}\n", test_addon_result.unwrap()).into_bytes()).unwrap();
            true
        }else{
            info!("{} doesn't look like a correct addon, keeping in the fs for review.", slug);
            failed.write(&slug.into_bytes()).unwrap();
            failed.write(&"\n".to_string().into_bytes()).unwrap();
            false
        }
    }).collect()
}

fn checkexistingaddons(){
    //let client = Client::new();
    let ts = time::now();
    let mut failed = File::create(Path::new("data").join(format!("failed_addons{}.out", timestamp(&ts)))).unwrap();
    let mut correct = File::create(Path::new("data").join(format!("correct_addons{}.out", timestamp(&ts)))).unwrap();
    let addon_re = Regex::new(".*:ofx.*").unwrap();
    let repos = Path::new("data").read_dir().unwrap()
        .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
        .filter_map(|entry| {
            let path = entry.as_ref().unwrap().path();
            let filename = path.as_path().file_name();
            match filename{
                Some(filename) => filename.to_str().map(|filename| filename.to_string()),
                None => None
            }
        })
        .filter(|entry| addon_re.is_match(entry));

    for slug in repos{
        let repo_name = slug.chars().skip_while(|&c| c != ':').collect::<String>();
        match test_correct_addon(&slug, &repo_name){
            Ok(reason) => {
                fs::remove_dir_all(&slug).expect("Couldn't remove repository directory");
                correct.write(&slug.into_bytes()).unwrap();
                correct.write(&format!(" {}\n", reason).into_bytes()).unwrap();
            },
            Err(_) => {
                error!("{} doesn't look like a correct addon, keeping in the fs for review.", slug);
                failed.write(&slug.into_bytes()).unwrap();
                failed.write(&"\n".to_string().into_bytes()).unwrap();
            }
        }
    }
}

fn main() {
    let matches = App::new("ofxaddons tests PR sender")
        .version("1.0")
        .author("Arturo Castro")
        .arg(Arg::with_name("checkonly")
                .short("c")
                .long("checkonly")
                .help("Only downloads potential addons and checks they are correct"))
        .arg(Arg::with_name("checkexisting")
                .short("e")
                .long("checkexisting")
                .help("Only checks already downloaded addons"))
        .arg(Arg::with_name("listonly")
                .short("l")
                .long("listonly")
                .help("Only lists potential addons by name"))
        .arg(Arg::with_name("repo")
                .short("r")
                .long("repo")
                .help("Only send pr to specified repository with format owner:repo")
                .value_name("REPO")
                .takes_value(true))
        .arg(Arg::with_name("owner")
                .short("o")
                .long("owner")
                .help("Only send pr to repositories owned by OWNER")
                .value_name("OWNER")
                .takes_value(true))
            .get_matches();
    let checkonly = matches.occurrences_of("checkonly") > 0;
    let listonly = matches.occurrences_of("listonly") > 0;
    let checkexisting = matches.occurrences_of("checkexisting") > 0;
    let only = matches.occurrences_of("repo") > 0;
    let owner = matches.value_of("owner");

    let mut oauth_token = String::new();
    File::open("secret/oauth.tok").unwrap().read_to_string(&mut oauth_token).unwrap();
    let oauth_token = oauth_token.trim();

    let mut repos = if !checkexisting && !only{
        build_repos_index(oauth_token, owner)
    }else if only{
        if let Some(repo) = matches.value_of("repo"){
            let owner_repo = repo.split(":").collect::<Vec<_>>();
            if owner_repo.len() == 2 {
                let owner = owner_repo[0];
                let repo = owner_repo[1];
                info!("Checking {}:{}", owner, repo);
                vec![Repository{
                    name: repo.to_owned(),
                    html_url: "https://github.com/".to_owned() + owner + "/" + repo,
                    url: "https://github.com/".to_owned() + owner + "/" + repo,
                    owner: Owner{
                        login: owner.to_owned(),
                    },
                    whitelisted: false,
                }]
            }else{
                panic!("REPO doesn't have format OWNER:REPO")
            }
        }else{
            panic!("REPO not specified")
        }
    }else{
        vec![]
    };

    if listonly{
        repos.sort();
        for repo in repos{
            println!("{}:{}", repo.owner.login, repo.name)
        }
    }else if checkexisting{
        info!("Checking exisiting");
        checkexistingaddons();
    }else if checkonly{
        info!("Only checking");
        checkaddons(&repos);
    }else if only{
        let repo = &repos[0];
        send_one_test_pr(repo, oauth_token);
    }else{
        info!("Sending all PRs");
        send_test_prs(&repos, oauth_token);
    }

}
