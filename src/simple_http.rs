use hyper::{self, Client};
use tokio_core;
use futures::Future;
use futures::stream::Stream;
use std::io;
use hyper_tls;

pub struct SimpleHttp{
    core: tokio_core::reactor::Core,
}

pub struct Response {
    pub body: String,
    pub headers: hyper::Headers,
    pub status: hyper::StatusCode,
}

impl SimpleHttp {
    pub fn new() -> io::Result<SimpleHttp> {
        tokio_core::reactor::Core::new().map(|core|
            SimpleHttp{
                core,
            }
        )
    }

    pub fn http_request(&mut self, req: hyper::Request) -> Result<Response, hyper::Error>{
        let handle = self.core.handle();
        let client = Client::new(&handle);

        let mut body = String::new();
        let mut headers = hyper::Headers::new();
        let mut status = hyper::StatusCode::Ok;
        let ret = {
            let work = client.request(req).and_then(|res|{
                status = res.status();
                headers = res.headers().clone();
                res.body().for_each(|chunk| {
                    body += &String::from_utf8(chunk.to_vec()).unwrap();
                    Ok(())
                })
            });
            self.core.run(work)
        };

        ret.map(|_| {
            Response{
                body,
                headers,
                status,
            }
        })
    }

    pub fn https_request(&mut self, req: hyper::Request) -> Result<Response, hyper::Error>{
        let handle = self.core.handle();
        let client = Client::configure()
            .connector(hyper_tls::HttpsConnector::new(4, &handle).unwrap())
            .build(&handle);

        let mut body = String::new();
        let mut headers = hyper::Headers::new();
        let mut status = hyper::StatusCode::Ok;
        let ret = {
            let work = client.request(req).and_then(|res|{
                status = res.status();
                headers = res.headers().clone();
                res.body().for_each(|chunk| {
                    body += &String::from_utf8(chunk.to_vec()).unwrap();
                    Ok(())
                })
            });
            self.core.run(work)
        };

        ret.map(|_| {
            Response{
                body,
                headers,
                status,
            }
        })
    }
}