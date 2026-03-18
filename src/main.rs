use std::{env, process};

const RADIX: u16 = 36;
const MAX_HEXTETS: usize = 7;
const MAX_TAG_LEN: usize = MAX_HEXTETS * 3;
const YGG_PREFIX: u16 = 0x200;

const FORMAT_VERSION: u8 = 1;
const RESERVED_MAX: u16 = 0x000f;
const PAD_BLOCK: u16 = 0x0000;

const FULL_BLOCK_SPACE: u16 = RADIX * RADIX * RADIX;
const FULL_BLOCK_ESCAPE_OFFSET: u16 = FULL_BLOCK_SPACE;
const PARTIAL1_OFFSET: u16 = FULL_BLOCK_ESCAPE_OFFSET + 0x0010;
const PARTIAL2_OFFSET: u16 = PARTIAL1_OFFSET + RADIX;

type CliResult<T> = Result<T, String>;

enum Command {
    Encode {
        input: String,
        fixed: bool,
        ipv6: bool,
    },
    Decode {
        input: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}\n\n{}", usage());
        process::exit(1);
    }
}

fn run() -> CliResult<()> {
    match parse_command(env::args().skip(1))? {
        Command::Encode { input, fixed, ipv6 } => {
            let blocks = encode_tag(&input)?;
            if ipv6 {
                println!("{}", format_ipv6(&blocks)?);
            } else if fixed {
                println!("{}", format_hextets(&pad_blocks(&blocks)?));
            } else {
                println!("{}", format_hextets(&blocks));
            }
        }
        Command::Decode { input } => {
            let blocks = parse_hextets(&input)?;
            println!("{}", decode_blocks(&blocks)?);
        }
    }

    Ok(())
}

fn parse_command<I>(args: I) -> CliResult<Command>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Err("missing subcommand".to_string());
    };

    match command.as_str() {
        "encode" => {
            let mut fixed = false;
            let mut ipv6 = false;
            let mut input = None;

            for arg in args {
                match arg.as_str() {
                    "--fixed" => fixed = true,
                    "--ipv6" => ipv6 = true,
                    flag if flag.starts_with('-') => {
                        return Err(format!("unknown flag for encode: {flag}"));
                    }
                    _ if input.is_some() => {
                        return Err("encode accepts exactly one input tag".to_string());
                    }
                    _ => input = Some(arg),
                }
            }

            let Some(input) = input else {
                return Err("encode requires a tag".to_string());
            };

            Ok(Command::Encode {
                input,
                fixed: fixed || ipv6,
                ipv6,
            })
        }
        "decode" => {
            let remaining: Vec<_> = args.collect();
            if remaining.len() != 1 {
                return Err("decode accepts exactly one encoded value".to_string());
            }

            Ok(Command::Decode {
                input: remaining.into_iter().next().expect("single item"),
            })
        }
        other => Err(format!("unknown subcommand: {other}")),
    }
}

fn encode_tag(input: &str) -> CliResult<Vec<u16>> {
    if input.is_empty() {
        return Err("tag must not be empty".to_string());
    }

    if input.len() > MAX_TAG_LEN {
        return Err(format!("tag is too long: max {MAX_TAG_LEN} characters"));
    }

    let normalized = input.to_ascii_lowercase();
    let indices = normalized
        .chars()
        .map(char_to_index)
        .collect::<CliResult<Vec<_>>>()?;

    let mut blocks = Vec::with_capacity(indices.len().div_ceil(3));
    for chunk in indices.chunks(3) {
        let block = match chunk {
            [c1, c2, c3] => {
                let value = c1 * RADIX * RADIX + c2 * RADIX + c3;
                if value <= RESERVED_MAX {
                    FULL_BLOCK_ESCAPE_OFFSET + value
                } else {
                    value
                }
            }
            [c1, c2] => PARTIAL2_OFFSET + (c1 * RADIX) + c2,
            [c1] => PARTIAL1_OFFSET + c1,
            _ => unreachable!("chunks(3) never yields empty chunks"),
        };
        blocks.push(block);
    }

    Ok(blocks)
}

fn decode_blocks(blocks: &[u16]) -> CliResult<String> {
    if blocks.is_empty() {
        return Err("encoded payload must contain at least one hextet".to_string());
    }

    if blocks.len() > MAX_HEXTETS {
        return Err(format!("too many hextets: max {MAX_HEXTETS}"));
    }

    let mut output = String::with_capacity(blocks.len() * 3);
    let mut saw_padding = false;

    for (index, block) in blocks.iter().copied().enumerate() {
        if block <= RESERVED_MAX {
            match block {
                PAD_BLOCK => {
                    saw_padding = true;
                    continue;
                }
                _ => {
                    return Err(format!(
                        "reserved/service hextet is not supported: {block:04x}"
                    ));
                }
            }
        }

        if saw_padding {
            return Err("payload hextet found after padding".to_string());
        }

        let short_tail = if block < FULL_BLOCK_ESCAPE_OFFSET {
            push_triplet(&mut output, block)?;
            false
        } else if block < PARTIAL1_OFFSET {
            push_triplet(&mut output, block - FULL_BLOCK_ESCAPE_OFFSET)?;
            false
        } else if block < PARTIAL2_OFFSET {
            let value = block - PARTIAL1_OFFSET;
            output.push(index_to_char(value)?);
            true
        } else if block < PARTIAL2_OFFSET + (RADIX * RADIX) {
            let value = block - PARTIAL2_OFFSET;
            output.push(index_to_char(value / RADIX)?);
            output.push(index_to_char(value % RADIX)?);
            true
        } else {
            return Err(format!(
                "hextet is outside format v{FORMAT_VERSION} ranges: {block:04x}"
            ));
        };

        if short_tail {
            for rest in &blocks[index + 1..] {
                if *rest != PAD_BLOCK {
                    return Err("only 0000 padding may follow a short final hextet".to_string());
                }
            }
            break;
        }
    }

    if output.is_empty() {
        return Err("encoded payload contains only padding".to_string());
    }

    Ok(output)
}

fn parse_hextets(input: &str) -> CliResult<Vec<u16>> {
    if input.is_empty() {
        return Err("encoded input must not be empty".to_string());
    }

    if input.contains("::") {
        return Err("compressed IPv6 notation with :: is not supported".to_string());
    }

    let mut blocks = input
        .split(':')
        .map(|part| {
            if part.is_empty() {
                return Err("empty hextet is not allowed".to_string());
            }
            if part.len() > 4 {
                return Err(format!("hextet is too long: {part}"));
            }
            u16::from_str_radix(part, 16).map_err(|_| format!("invalid hextet: {part}"))
        })
        .collect::<CliResult<Vec<_>>>()?;

    if blocks.len() == MAX_HEXTETS + 1 {
        if blocks[0] != YGG_PREFIX {
            return Err(format!(
                "expected IPv6 prefix {YGG_PREFIX:04x}, got {:04x}",
                blocks[0]
            ));
        }
        blocks.remove(0);
    }

    Ok(blocks)
}

fn char_to_index(ch: char) -> CliResult<u16> {
    match ch {
        'a'..='z' => Ok((ch as u8 - b'a') as u16),
        '0'..='9' => Ok((ch as u8 - b'0') as u16 + 26),
        _ => Err(format!("unsupported character: {ch}")),
    }
}

fn index_to_char(index: u16) -> CliResult<char> {
    match index {
        0..=25 => Ok((b'a' + index as u8) as char),
        26..=35 => Ok((b'0' + (index as u8 - 26)) as char),
        _ => Err(format!("invalid alphabet index: {index}")),
    }
}

fn push_triplet(output: &mut String, value: u16) -> CliResult<()> {
    let c1 = value / (RADIX * RADIX);
    let rest = value % (RADIX * RADIX);
    let c2 = rest / RADIX;
    let c3 = rest % RADIX;

    output.push(index_to_char(c1)?);
    output.push(index_to_char(c2)?);
    output.push(index_to_char(c3)?);
    Ok(())
}

fn pad_blocks(blocks: &[u16]) -> CliResult<Vec<u16>> {
    if blocks.len() > MAX_HEXTETS {
        return Err(format!("payload exceeds {MAX_HEXTETS} hextets"));
    }

    let mut padded = blocks.to_vec();
    padded.resize(MAX_HEXTETS, PAD_BLOCK);
    Ok(padded)
}

fn format_hextets(blocks: &[u16]) -> String {
    blocks
        .iter()
        .map(|block| format!("{block:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_ipv6(blocks: &[u16]) -> CliResult<String> {
    let padded = pad_blocks(blocks)?;
    let mut all = Vec::with_capacity(MAX_HEXTETS + 1);
    all.push(YGG_PREFIX);
    all.extend(padded);
    Ok(format_hextets(&all))
}

fn usage() -> String {
    format!(
        "Usage:
  ygg-futhark encode [--fixed] [--ipv6] <tag>
  ygg-futhark decode <hextets|0200:...>

Format v{FORMAT_VERSION}:
  alphabet      [a-z0-9]
  max tag       {MAX_TAG_LEN} chars
  raw blocks    1..7 hextets
  fixed blocks  7 hextets padded with 0000
  ipv6 mode     0200:<7 hextets>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reference_triplet_from_the_concept() {
        let encoded = encode_tag("mak").expect("encode");
        assert_eq!(encoded, vec![0x3cca]);
        assert_eq!(decode_blocks(&encoded).expect("decode"), "mak");
    }

    #[test]
    fn round_trips_tags_with_trailing_a() {
        for tag in ["a", "maka", "zaa", "aaaaaa", "maksima"] {
            let encoded = encode_tag(tag).expect("encode");
            assert_eq!(decode_blocks(&encoded).expect("decode"), tag);
        }
    }

    #[test]
    fn round_trips_partial_final_blocks() {
        for tag in ["maksim", "maksim4", "maksim42", "42", "4"] {
            let encoded = encode_tag(tag).expect("encode");
            assert_eq!(decode_blocks(&encoded).expect("decode"), tag);
        }
    }

    #[test]
    fn fixed_format_pads_to_seven_hextets() {
        let encoded = encode_tag("maksim42").expect("encode");
        let fixed = pad_blocks(&encoded).expect("pad");
        assert_eq!(fixed.len(), MAX_HEXTETS);
        assert_eq!(format_hextets(&fixed), "3cca:5c4c:bac8:0000:0000:0000:0000");
        assert_eq!(decode_blocks(&fixed).expect("decode"), "maksim42");
    }

    #[test]
    fn ipv6_format_is_decodable() {
        let encoded = encode_tag("maksim42").expect("encode");
        let ipv6 = format_ipv6(&encoded).expect("ipv6");
        let parsed = parse_hextets(&ipv6).expect("parse");
        assert_eq!(parsed.len(), MAX_HEXTETS);
        assert_eq!(decode_blocks(&parsed).expect("decode"), "maksim42");
    }

    #[test]
    fn rejects_unsupported_characters() {
        let error = encode_tag("maksim-42").expect_err("invalid input");
        assert!(error.contains("unsupported character"));
    }

    #[test]
    fn rejects_payload_after_padding() {
        let error = decode_blocks(&[0x3cca, PAD_BLOCK, 0x4798]).expect_err("invalid ordering");
        assert_eq!(error, "payload hextet found after padding");
    }

    #[test]
    fn rejects_non_padding_after_short_tail() {
        let short_tail = encode_tag("ma").expect("encode")[0];
        let full = encode_tag("ksi").expect("encode")[0];
        let error = decode_blocks(&[short_tail, full]).expect_err("invalid ordering");
        assert_eq!(error, "only 0000 padding may follow a short final hextet");
    }

    #[test]
    fn rejects_empty_or_too_long_tags() {
        assert!(encode_tag("").is_err());
        assert!(encode_tag("abcdefghijklmnopqrstuv").is_err());
    }
}