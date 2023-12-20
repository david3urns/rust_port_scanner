/*
VERSION 1.0
A very basic port scanner written in rust, includes input validation for the IP address
and port number (currently invalid port sends you back to the main menu, will update further
at a later date)
Gives the options to run a TCP scan against a single port, common ports, port list, port range,
or all ports. Note threading is not currently enabled so running against several ports or all
ports will take a while.
Written by David Burns
 */

use ::std::io::{stdin, stdout, Read, self, Write};
use ::std::net::{TcpStream, IpAddr};
use std::time::Duration;
use std::thread::sleep;

fn main(){

    //function to create the menu to select single port, most common ports, or port range
    fn menu(){
        loop {
            clear_screen();
            banner("Port Scanner");

            println!("");
            println!("1. Single Port");
            println!("2. Common Ports");
            println!("3. Port List");
            println!("4. Port Range");
            println!("5. All Ports");
            println!("6. Exit");
            println!("");
            print!("Please enter the type of scan you would like to run (1-6): ");

            io::stdout().flush().unwrap();
            let mut menu_select = String::new();
            io::stdin().read_line(&mut menu_select).unwrap();

            match menu_select.trim() {
                "1" => single_port(),
                "2" => common_ports(),
                "3" => port_list(),
                "4" => port_range(),
                "5" => all_ports(),
                "6" => {
                    clear_screen();
                    println!("Exiting...");
                    sleep_time(3);
                    std::process::exit(0);
                }
                _ => {
                    println!("Invalid input, please enter a number between 1 and 5.");
                    sleep_time(5);
                }
            }
        }
    }

//function to scan a single port number provided by the user
fn single_port(){
    clear_screen();
    banner("Single Port Scan");

    //get IP address
    let mut ip_address = String::new();
    print!("Please enter the IP address of the target machine: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ip_address).unwrap();
    let ip_address = ip_address.trim();

    //validate IP address
    let ip_addr = match validate_ip(ip_address) {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("Invalid IP Address: {}", err);
            pause();
            return;
        }
    };

    //get port number
    let mut port_str = String::new();
    print!("Please enter the port number to scan: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut port_str).unwrap();

    //validate port number
    let port: u16 = match port_str.trim().parse() {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Failed to parse port number {}.", err);
            pause();
            return;
        }
    };

    //run the scan
    match TcpStream::connect((ip_addr, port)) {
        Ok(_) => println!("Port {} is \x1b[0;32mopen\x1b[0m.", port),
        Err(_) => println!("Port {} is \x1b[0;31mclosed\x1b[0m.", port),
    }


    //pause to allow user to view results, clears screen, then returns to the menu
    pause();
    clear_screen();
    menu();
}


//function to scan a preset list of most common port numbers
fn common_ports(){
    clear_screen();
    banner("Common Port Scan");
    let mut closed_count = 0;

    //get IP address
    let mut ip_address = String::new();
    print!("Please enter the IP address of the target machine: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ip_address).unwrap();
    let ip_address = ip_address.trim();

    //validate IP address
    let ip_addr = match validate_ip(ip_address) {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("Invalid IP Address: {}", err);
            pause();
            return;
        }
    };

    //list of top ports (631 added as part of testing)
    let top_ports = vec![21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 631, 1433, 3306, 3389, 5632, 5900, 25565];

    for port in top_ports {
        match TcpStream::connect((ip_addr, port)) {
            Ok(_) => println!("Port {} is \x1b[0;32mopen\x1b[0m.", port),
            Err(_) => closed_count += 1,
        }

    }

    //pause to allow user to view results
    println!("Scan completed, {} ports were \x1b[0;31mclosed\x1b[0m.", closed_count);
    pause();
    clear_screen();
    menu();
}


//function to scan a list of user provided ports:
fn port_list(){
    clear_screen();
    banner("Port List Scan");
    let mut closed_count = 0;

    //get IP address
    let mut ip_address = String::new();
    print!("Enter IP Address: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ip_address).unwrap();
    let ip_address = ip_address.trim();

    //validate IP address
    let ip_addr = match validate_ip(ip_address) {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("Invalid IP Address: {}", err);
            pause();
            return;
        }
    };

     //get list of ports:
     let mut ports_str = String::new();
     print!("Enter a list of ports to scan, separated by a comma (,): ");
     io::stdout().flush().unwrap();
     io::stdin().read_line(&mut ports_str).unwrap();

     //trim and split ports
     let ports: Vec<u16> = ports_str
         .trim()
         .split(',')
         .filter_map(|s| s.trim().parse().ok())
         .collect();
 
     

    //run the scan:
    for port in ports {
        match TcpStream::connect((ip_addr, port)) {
            Ok(_) => println!("Port {} is \x1b[0;32mopen\x1b[0m.", port),
            Err(_) => closed_count += 1,
        }
    }
    
    //pause to allow user to view results
    println!("Scan completed, {} ports were \x1b[0;31mclosed\x1b[0m.", closed_count);
    pause();
    clear_screen();
    menu();
}


//function to scan a range of ports:
fn port_range(){
    clear_screen();
    banner("Port Range Scan");
    let mut closed_count = 0;

    //get IP address
    let mut ip_address = String::new();
    print!("Enter IP Address: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ip_address).unwrap();
    let ip_address = ip_address.trim();

    //validate IP address
    let ip_addr = match validate_ip(ip_address) {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("Invalid IP Address: {}", err);
            pause();
            return;
        }
    };

    //get starting port number
    let mut start_port_str = String::new();
    print!("Enter starting port number: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut start_port_str).unwrap();
    let start_port: u16 = match start_port_str.trim().parse() {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Failed to parse port number: {}", err);
            return;
        }
    };

    //get ending port number
    let mut end_port_str = String::new();
    print!("Enter starting port number: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut end_port_str).unwrap();
    let end_port: u16 = match end_port_str.trim().parse() {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Failed to parse port number: {}", err);
            return;
        }
    };

    //run the scan
    for port in start_port..=end_port{
        match TcpStream::connect((ip_addr,port)) {
            Ok(_) => println!("Port {} is \x1b[0;32mopen\x1b[0m.", port),
            Err(_) => closed_count += 1,
        }
    }

    //pause to allow user to review output
    println!("Scan completed, {} ports were \x1b[0;31mclosed\x1b[0m.", closed_count);
    pause();
    clear_screen();
    menu();
}


//scan all ports
fn all_ports(){
    clear_screen();
    banner("All Ports Scan");
    let mut closed_count = 0;

    //get IP address
    let mut ip_address = String::new();
    print!("Enter IP Address: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ip_address).unwrap();
    let ip_address = ip_address.trim();

    //validate IP address
    let ip_addr = match validate_ip(ip_address) {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("Invalid IP Address: {}", err);
            pause();
            return;
        }
    };

    //declare starting port of 1
    let start_port_str = "1";
    io::stdout().flush().unwrap();
    let start_port: u16 = match start_port_str.trim().parse() {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Failed to parse port number: {}", err);
            return;
        }
    };


    //declare end port of 65535
    let end_port_str = "65535";
    io::stdout().flush().unwrap();
    let end_port: u16 = match end_port_str.trim().parse() {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Failed to parse port number: {}", err);
            pause();
            return;
        }
    };

    //run the scan
    for port in start_port..=end_port{
        match TcpStream::connect((ip_addr,port)) {
            Ok(_) => println!("Port {} is \x1b[0;32mopen\x1b[0m.", port),
            Err(_) => closed_count += 1,
            //Err(_) => println!("Port {} is \x1b[0;31mclosed\x1b[0m.", port),
        }
    }

    //pause to allow user to view output
    println!("Scan completed, {} ports were \x1b[0;31mclosed\x1b[0m.", closed_count);
    pause();
    clear_screen();
    menu();
}
menu();
}


//function to create the banner
fn banner(ban_title: &str) {
    let h_border = "═";
    let v_border = "║";
    let tl_corner = "╔";
    let tr_corner = "╗";
    let bl_corner = "╚";
    let br_corner = "╝";

    //determine the length of the title string
    let title_length = ban_title.len();

    //print the actual box:
    println!("{}{}{}{}{}", tl_corner, h_border, h_border.repeat(title_length), h_border, tr_corner);
    println!("{}{}{}{}{}", v_border, " ", ban_title, " ", v_border);
    println!("{}{}{}{}{}", bl_corner, h_border, h_border.repeat(title_length), h_border, br_corner);


    //future feature to justify and add color to the banner and text
}

fn clear_screen(){
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
    }

fn sleep_time(sleep_time_input: u64){
    sleep(Duration::from_secs(sleep_time_input));
}

fn pause(){
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

fn validate_ip(ip_address: &str) -> Result <IpAddr, String> {
    ip_address
        .parse()
        .map_err(|_| String::from("Invalid IP Address."))
}