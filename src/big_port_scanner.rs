use ::std::io::{self, Write};
use ::std::net::{TcpStream, SocketAddr};
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
            println!("3. Port Range");
            println!("4. Exit");
            println!("");
            println!("Please select the type of scan you would like to run below:");

            io::stdout().flush().unwrap();
            let mut menu_select = String::new();
            io::stdin().read_line(&mut menu_select).unwrap();

            match menu_select.trim() {
                "1" => single_port(),
                "2" => common_ports(),
                "3" => port_range(),
                "4" => {
                    clear_screen();
                    println!("Exiting...");
                    sleep_time(3);
                    std::process::exit(0);
                }
                _ => {
                    println!("Invalid input, please enter a number between 1 and 4.");
                    sleep_time(5);
                }
            }
        }
    }
}



//function to scan a single port number provided by the user
fn single_port(){
    println!("Scan a single port.")
    sleep_time(3);
    clear_screen();
    menu();
}


//function to scan a preset list of most common port numbers
fn common_ports(){
    println!("Scan common ports.")
    sleep_time(3);
    clear_screen();
    menu();
}



//function to scan a range of ports:
fn port_range(){
    println!("Scan a port range.")
    sleep_time(3);
    clear_screen();
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
