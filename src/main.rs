extern crate hyper;
extern crate json;
extern crate time;
extern crate clap;
extern crate regex;
extern crate walkdir;

use hyper::client::Client;
use hyper::header;
use hyper::status::StatusCode;

use clap::{Arg, App};

use regex::Regex;

use walkdir::WalkDir;

use std::io::{Read, Write, Result as IoResult};
use std::io::BufReader;
use std::io::BufRead;
use std::fs::{self, File};
use std::path::Path;
use std::thread;
use std::collections::{HashMap, HashSet};
use std::process::{Command, Output};

static OFXADDONS_LOGIN: &'static str = "ofxaddons-tests";

#[derive(Debug)]
struct Owner{
    login: String
}

#[derive(Debug)]
struct Repository {
    name: String,
    html_url: String,
    url: String,
    owner: Owner,
}

fn git_clone(repo: &str) -> IoResult<Output>{
    println!("Cloning {}", repo);
    Command::new("git")
            .arg("clone")
            .arg(repo)
            .output()
}

fn git_shallow_clone(repo: &str, path: &str) -> IoResult<Output>{
    println!("Cloning {}", repo);
    Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--branch")
            .arg("master")
            .arg(repo)
            .arg(path)
            .output()
}

fn git_add(repo: &str, args: &str) -> IoResult<Output>{
    Command::new("git")
            .arg("add")
            .arg(args)
            .current_dir(repo)
            .output()
}

fn git_commit(repo: &str, message: &str) -> IoResult<Output>{
    Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg(message)
            .current_dir(repo)
            .output()
}

fn git_push(repo: &str, url: &str) -> IoResult<Output>{
    Command::new("git")
            .arg("push")
            .arg(url)
            .arg("master")
            .current_dir(repo)
            .output()
}

fn test_correct_addon(repo_path: &str, addon_name: &str) -> bool{
    let src_path = Path::new(repo_path).join("src");
    let libs_path = Path::new(repo_path).join("libs");
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

    let of_headers_file = BufReader::new(File::open("of_headers").unwrap());
    let of_headers = of_headers_file.lines().map(|line| line.unwrap()).collect::<Vec<_>>();
    let of_headers_regex = of_headers.iter()
        .map(|header| Regex::new(&format!("#include\\s*\"{}\"",header)).unwrap())
        .collect::<Vec<_>>();

    let incldues_of_source = has_src && {
        WalkDir::new(src_path).into_iter().filter_map(|e| e.ok())
            .filter(|entry| entry.file_type().is_file())
            //.map(|entry| entry.path())
            //.inspect(|path| println!("testing {:?}", path))
            .filter(|entry| entry.path().extension().is_some())
            //.inspect(|path| println!("has extension {:?}", path.extension().unwrap()))
            .filter(|entry|
                entry.path().extension().unwrap() == "h" ||
                entry.path().extension().unwrap() == "hpp"||
                entry.path().extension().unwrap() == "c"||
                entry.path().extension().unwrap() == "cpp"||
                entry.path().extension().unwrap() == "h"||
                entry.path().extension().unwrap() == "mm")
            .any(|entry|{
                let mut source_file = File::open(entry.path()).unwrap();
                let mut source = String::new();
                source_file.read_to_string(&mut source).is_ok() &&
                    of_headers_regex.iter().any(|header| header.is_match(&source))
                //of_headers.iter().any(|header| source.contains(&format!("#include \"{}\"", header)))

            })
    };

    has_src_header || incldues_of_source || has_correct_lib
}

fn build_repos_index(oauth_token: &str, checkonly: bool) -> Vec<Repository>{
    let mut client = Client::new();
    let mut url = if checkonly{
        "https://api.github.com/search/repositories?q=ofx+in:name&per_page=100".to_string()
    }else{
        "https://api.github.com/search/repositories?q=ofx+in:name+user:arturoc&per_page=100".to_string()
    };

    let mut repos = vec![];

    let oauth = header::Bearer{
        token: oauth_token.to_string(),
    };

    println!("Next: {}", url);
    loop{
        let mut res = client.get(&url)
                    .header(header::UserAgent("ofxaddons".to_string()))
                    .header(header::Authorization(oauth.clone()))
                    .send()
                    .unwrap();

        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();
        match res.status{
            hyper::Ok => {},
            _ => {
                println!("{}", body);
                break;
            }
        };

        let parsed = json::parse(&body).unwrap();
        let new_repos = parsed["items"].members()
            .filter(|&repo| repo["name"].to_string().starts_with("ofx"))
            .filter(|&repo| &repo["name"].to_string()!="ofx")
            .filter(|&repo| &repo["name"].to_string()!="ofx4j")
            .filter(|&repo| &repo["name"].to_string()!="ofxAddonTemplate")
            .filter(|&repo| !&repo["name"].to_string().starts_with("ofx-"))
            .filter(|&repo| !&repo["name"].to_string().starts_with("ofx_"))
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
            });

        repos.extend(new_repos);

        match res.headers.get_raw("Link"){
            Some(next_link) => if !next_link.is_empty(){
                let ratelimit = String::from_utf8(res.headers.get_raw("X-RateLimit-Limit").unwrap()[0].clone()).unwrap();
                let remaining = String::from_utf8(res.headers.get_raw("X-RateLimit-Remaining").unwrap()[0].clone()).unwrap();
                let reset = String::from_utf8(res.headers.get_raw("X-RateLimit-Reset").unwrap()[0].clone()).unwrap();
                let reset = time::Timespec{
                    sec: reset.parse::<i64>().unwrap() + 10,
                    nsec: 0
                };

                let link = String::from_utf8(res.headers.get_raw("Link").unwrap()[0].clone()).unwrap();
                let rels: HashMap<_,_> = link.split(",")
                    .map(|rel|{
                        let mut link_rel = rel.split(";");
                        let link = link_rel.next().unwrap();
                        let rel = link_rel.next().unwrap();
                        let rel = rel.split("\"").skip(1).next().unwrap().to_string();
                        let url = link[1..link.len()-1].to_string();
                        (rel, url)
                    })
                    .collect();

                match rels.get("next"){
                    Some(next) => {
                        url = next.clone();
                        if remaining.parse::<u32>().unwrap()==0 {
                            let pause = reset - time::now().to_timespec();
                            println!("pausing for {}s", pause.num_seconds());
                            thread::sleep(pause.to_std().unwrap());
                            client = Client::new();
                        }
                    },
                    None => break
                }

                println!("{}/{} Next: {}", remaining, ratelimit, url);
            }else{
                break;
            },
            None => break
        }
    }

    repos
}

fn send_test_prs(repos: &Vec<Repository>, oauth_token: &str){
    let mut prs_sent = String::new();
    let prs_sent = match File::open("prs_sent"){
        Ok(mut file) => {
            file.read_to_string(&mut prs_sent).unwrap();
            prs_sent.lines().map(|line| line.to_string()).collect::<HashSet<String>>()
        }
        Err(_) => HashSet::new(),
    };

    let oauth = header::Bearer{
        token: oauth_token.to_string(),
    };

    git_clone("https://github.com/openframeworks/ofxAddonTemplate").expect("Couldn't clone ofxAddonTemplate");
    let commit_title = "Adding travis and appveyor cotinuous integration tests";


    let client = Client::new();
    let mut new_prs_sent = HashSet::new();
    for repo in repos.iter().filter(|&repo| !prs_sent.contains(&(repo.owner.login.clone() + ":" + &repo.name))).take(1){
        let commit_msg = format!(
"This is an automated pull request that enables continous integration testing for openFrameworks
addons. We've done our best to check that this repository actually contains an openFrameworks
addon but if it doesn't or this addon is not maintained anymore or you are simply not interested in
testing this addon, we are really sorry for bothering you. You can just close or ignore this PR and
no further communications will be sent to this repository.

Before merging this PR you'll need to create an account on https://travis-ci.org and
https://ci.appveyor.com using your github account and enable the tests for this addon there.

Once you have created an account at travis.org you can enable tests for this addon at
https://travis-ci.org/{owner}/{repo}

And for windows at https://ci.appveyor.com/projects/new

This PR includes test files for travis and appveyor ci services, once you merge it any new commit
or PR to your repository will compile this addon for every supported platform against the latest
openFrameworks.

This new files can be customized but we recommend to not touch them much except for commenting or
uncommenting the different platfoms to test. That way we can ensure that the addon will work for
any standard setup. The testing can be further customized (for example to install some dependencies
in certain platforms by using some scripts in scripts/platforms there's more instructions on how
to use them in the .travis.yml and appveyor.yml files in this PR.

Once your addon tests are working you can add a badge to your readme files so people using your
addon can see the build status:

For travis you can just copy and paste the following markdown:

```
[![Build status](https://travis-ci.org/{owner}/{repo}.svg?branch=master)](https://travis-ci.org/{owner}/{repo})
```

which will look like: [![Build status](https://travis-ci.org/{owner}/{repo}.svg?branch=master)](https://travis-ci.org/{owner}/{repo})

For appveyor you can find the badge code at https://ci.appveyor.com/project/{owner}/{repo}/settings/badges

If you have any doubt you can ask directly in this PR or in the openFrameworks forum",
        owner=repo.owner.login, repo=repo.name);

        let fork_url = "https://api.github.com/repos/".to_string() + &repo.owner.login + "/" + &repo.name + "/forks";
        let mut res = client.post(&fork_url)
            .header(header::UserAgent("ofxaddons".to_string()))
            .header(header::Authorization(oauth.clone()))
            .send()
            .unwrap();
        match res.status{
            hyper::Ok | StatusCode::Accepted => {},
            _ => {
                let mut body = String::new();
                res.read_to_string(&mut body).unwrap();
                println!("Error forking: {} {}", res.status, body);
                break;
            }
        }

        let repo_check_url = "https://api.github.com/repos/".to_string() + OFXADDONS_LOGIN + "/" + &repo.name;
        loop{
            thread::sleep(std::time::Duration::from_secs(10));
            let res = client.get(&repo_check_url)
                .header(header::UserAgent("ofxaddons".to_string()))
                .header(header::Authorization(oauth.clone()))
                .send()
                .unwrap();
            match res.status{
                hyper::Ok => break,
                _ => println!("Fork hasn't finished yet, waiting 10s"),
            }
        }

        let repo_url = "https://".to_string() + oauth_token + "@github.com/" + OFXADDONS_LOGIN + "/" + &repo.name;

        git_clone(&repo_url).expect("Failed cloning");

        let is_correct_addon = test_correct_addon(&repo.name, &repo.name);
        if !is_correct_addon{
            println!("{}:{} doesn't look like a correct addon.", repo.owner.login, repo.name);
        }
        let travis = repo.name.clone() + "/.travis.yml";
        let appveyor = repo.name.clone() + "/.appveyor.yml";

        if is_correct_addon && !Path::new(&travis).exists() && !Path::new(&appveyor).exists(){
            fs::copy("ofxAddonTemplate/.travis.yml", travis)
                .expect("Couldn't copy .travis.yml");
            fs::copy("ofxAddonTemplate/.appveyor.yml", appveyor)
                .expect("Couldn't copy .appveyor.yml");

            let out = git_add(&repo.name, ".travis.yml").expect("git add .travis.yml failed");
            if !out.status.success(){
                panic!("git add .travis.yml failed");
            }
            let out = git_add(&repo.name, ".appveyor.yml").expect("git add .appveyor.yml failed");
            if !out.status.success(){
                panic!("git add .appveyor.yml failed");
            }
            let message = commit_title.to_string() + "\n\n" + &commit_msg;
            let out = git_commit(&repo.name, &message).expect("git commit test files failed");
            if !out.status.success(){
                panic!("git commit test files failed");
            }
            let out = git_push(&repo.name, &repo_url).expect("git push failed");
            if !out.status.success(){
                panic!("git push failed");
            }

            let pr_url = "https://api.github.com/repos/".to_string() + &repo.owner.login + "/" + &repo.name + "/pulls";
            let body = format!("{{
                \"title\": \"{}\",
                \"body\": \"{}\",
                \"base\": \"master\",
                \"head\": \"{}:master\"
            }}", commit_title, commit_msg.replace("\n","\\n"), OFXADDONS_LOGIN);

            let mut res = client.post(&pr_url)
                .header(header::UserAgent("ofxaddons".to_string()))
                .header(header::Authorization(oauth.clone()))
                .body(&body)
                .send()
                .unwrap();
            if res.status.is_success() {
                new_prs_sent.insert(repo.owner.login.clone() + ":" + &repo.name);
            }else{
                let mut body = String::new();
                res.read_to_string(&mut body).unwrap();
                println!("Error creating PR: {} {}", res.status, body);
                break;
            }
        }else{
            println!("{} already has test config, skipping", &repo.name);
        }

        fs::remove_dir_all(&repo.name).expect("Couldn't remove repository directory");

        let rm_url = "https://api.github.com/repos/".to_string() + OFXADDONS_LOGIN + "/" + &repo.name;
        let mut res = client.delete(&rm_url)
            .header(header::UserAgent("ofxaddons".to_string()))
            .header(header::Authorization(oauth.clone()))
            .send()
            .unwrap();
        if !res.status.is_success() {
            let mut body = String::new();
            res.read_to_string(&mut body).unwrap();
            println!("Error removing repo: {} {}", res.status, body);
            break;
        }
    }

    fs::remove_dir_all("ofxAddonTemplate").expect("Couldn't remove repository directory");

    new_prs_sent.extend(prs_sent.into_iter());
    let mut prs_sent_file = File::create("prs_sent").unwrap();
    for pr in new_prs_sent{
        prs_sent_file.write(&(pr + "\n").into_bytes()).unwrap();
    }
}

fn timestamp(ts: &time::Tm) -> String{
    format!("{}{:02}{:02}{:02}{:02}{:02}", 1900 + ts.tm_year, ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec)
}

fn checkaddons(repos: &Vec<Repository>){
    //let client = Client::new();
    let ts = time::now();
    let mut failed = File::create(format!("failed_addons{}.out", timestamp(&ts))).unwrap();
    let mut correct = File::create(format!("correct_addons{}.out", timestamp(&ts))).unwrap();
    for repo in repos.iter(){
        let slug = format!("{}:{}", repo.owner.login, repo.name);
        git_shallow_clone(&repo.html_url, &slug).expect("Failed cloning");
        if !test_correct_addon(&slug, &repo.name){
            println!("{} doesn't look like a correct addon, keeping in the fs for review.", slug);
            failed.write(&slug.into_bytes()).unwrap();
            failed.write(&"\n".to_string().into_bytes()).unwrap();
        }else{
            fs::remove_dir_all(&slug).expect("Couldn't remove repository directory");
            correct.write(&slug.into_bytes()).unwrap();
            correct.write(&"\n".to_string().into_bytes()).unwrap();
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
            .get_matches();
    let checkonly = matches.occurrences_of("checkonly") > 0;

    let mut oauth_token = String::new();
    File::open("oauth.tok").unwrap().read_to_string(&mut oauth_token).unwrap();
    let oauth_token = oauth_token.trim();

    let repos = build_repos_index(oauth_token, checkonly);

    if checkonly{
        checkaddons(&repos);
    }else{
        send_test_prs(&repos, oauth_token);
    }

}
