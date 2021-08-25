/// This code is for testing purposes ONLY
/// This should never be used in production
use clap::Clap;
use schnorrkel::{signing_context, Keypair, Signature};
use rand::Rng;

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap)]
struct Opts {
    /// Used to specify which Rust function to test
    test: String
}


fn main() {
    let opts: Opts = Opts::parse();

    if opts.test == "sign" {
        for _ in 0..10 {
            // generate random keys
            let keypair: Keypair = Keypair::generate();
            // generate random context
            let random_ctx = rand::thread_rng().gen::<[u8; 8]>();
            let ctx = signing_context(&random_ctx);
            // generate random message
            let random_msg = rand::thread_rng().gen::<[u8; 8]>();
            // produce signature
            let sig: Signature = keypair.sign(ctx.bytes(&random_msg));
            // print keys, context, message, and signature to standard output
            println!("{:?}", random_ctx);
            println!("{:?}", random_msg);
            println!("{:?}", keypair.public.to_bytes());
            println!("{:?}", sig.to_bytes());
        }
        
    }
    else {
        println!("don't recognize this");
    }
}
