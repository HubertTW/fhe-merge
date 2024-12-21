use bincode;
use std::fs;
use std::env;
use std::fs::File;
use glob::glob;
use std::io::BufRead;
use std::io::{BufReader, Cursor, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use rayon::prelude::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use tfhe::integer::{RadixCiphertext};
use tfhe::prelude::*;
use tfhe::prelude::{FheDecrypt, FheEncrypt, FheTrivialEncrypt};
use tfhe::{set_server_key, ClientKey, FheUint, FheUint16, FheUint16Id, FheUint8, FheUint8Id, ServerKey, FheUint32Id, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("start");
    let dir_path = "/home/henry/fhe-merge";
    let string_size = [2,1];

    println!("[debug]client key");
    let mut byte_vec = fs::read("client_key.bin")?;
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;
    println!("server key");
    let mut file = fs::read("server_key.bin")?;
    let sk = deserialize_sk(file.as_slice())?;
    set_server_key(sk);

    let mut blank = vec![FheUint16::encrypt_trivial(32u8)];


    println!("deserializing encrypted slice_string_i.bin...");
    let mut entries: Vec<_> = fs::read_dir(dir_path)?
        .filter_map(Result::ok)
        .filter(|entry| {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            file_name.starts_with("sanitized_string_") && file_name.ends_with(".bin") // 篩選符合條件的檔案
        })
        .collect();

    // 按檔案名稱中的數字部分排序
    entries.sort_by_key(|entry| {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        extract_number(&file_name) // 提取數字部分
    });

    let mut enc_string_arr = vec![];

    let mut count = 0;
    for entry in entries {
        println!("reading file {:?}", entry);
        let path = entry.path();
        let file = fs::read(&path)?;
        enc_string_arr.push(deserialize_str(&file, string_size[count])?);
        enc_string_arr.push(blank.clone());
        count+=1;

    }

    let  enc_merge = enc_string_arr.into_iter().flat_map(|v| v).collect();

    println!("serialization...");
    let mut serialized_enc_str = Vec::new();
    for i in &enc_merge {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("sanitized_payload.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");

    println!("[debug] decrypt sanitized result");
    let s = decryptStr(enc_merge, &ck);
    println!("the sanitized res is {:?}", s);

    Ok(())




}
fn load_from_file(file_path: &str) -> Vec<usize> {
    if let Ok(file) = File::open(file_path) {
        let reader = BufReader::new(file);
        let mut indices = Vec::new();

        for line in reader.lines() {

            if let Ok(line) = line {

                if let Ok(value) = line.parse::<usize>() {
                    indices.push(value);
                }
            }
        }
        indices
    } else {
        Vec::new()
    }
}


fn extract_number(file_name: &str) -> u32 {
    file_name
        .split('_')
        .last() // 取得最後一部分，例如 "0.bin"
        .and_then(|s| s.strip_suffix(".bin")) // 去除後綴
        .and_then(|s| s.parse::<u32>().ok()) // 轉換成數字
        .unwrap_or(0) // 預設為 0
}

pub fn decryptStr(content: Vec<FheUint<FheUint16Id>>, ck: &ClientKey) -> String {
    let mut v = vec![];

    for byte in &content {
        v.push(byte.decrypt(&ck));
    }

    let measurements = 100;
    let mut elapsed_times: Vec<Duration> = Vec::new();

    for _ in 0..measurements {
        let start = Instant::now();
        for byte in &content {
            let temp: u8 = byte.decrypt(&ck);
        }
        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);
        //println!("Elapsed time: {:?}", elapsed);
    }

    // 計算平均經過時間
    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

    println!("Average decryption elapsed time: {:?}", average_elapsed);

    println!("{:?}", v);
    String::from_utf8(v).unwrap()

}
fn deserialize_sk(serialized_data: &[u8]) -> Result<ServerKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let sk: ServerKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(sk)
}

fn deserialize_ck(serialized_data: &[u8]) -> Result<ClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: ClientKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn deserialize_str(
    serialized_data: &[u8],
    content_size: u8
) -> Result<Vec<FheUint<FheUint16Id>>, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let mut v: Vec<FheUint<FheUint16Id>> = vec![];
    for _ in 0..content_size{
        // length of received string
        v.push(bincode::deserialize_from(&mut to_des_data)?);
    }
    Ok(v)
}


