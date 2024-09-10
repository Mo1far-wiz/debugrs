use std::{num::ParseIntError, str::FromStr};
use thiserror::Error;

pub enum UserInstruction {
    AddBreakpoint { address: u64 },
    ContinueUntilBreakpoint,
    ContinueUntilSyscall,
    ShowHelp,
    ShowMemory { address: u64 },
    WriteToMemory {address: u64, value: i64},
    ShowRegisters,
    SingleStep,
    FindInMemory {value: i64}
}

#[derive(Error, Debug)]
pub enum UserInstructionParseError {
    #[error("Unknown instruction")]
    UnknownInstruction,
    #[error("Address should start with `0x`")]
    AddressShouldStartWith0x,
    #[error("Can't parse value")]
    ValueParseError,
    #[error("Could not parse address: {0}")]
    UnparseableAddress(ParseIntError),
    #[error("Could not parse value: {0}")]
    UnparseableValue(ParseIntError),
    #[error("Not enough arguments for instruction")]
    NotEmoughArguments,
}

impl FromStr for UserInstruction {
    type Err = UserInstructionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "c" => Ok(UserInstruction::ContinueUntilBreakpoint),
            "s" => Ok(UserInstruction::ContinueUntilSyscall),
            "h" => Ok(UserInstruction::ShowHelp),
            "r" => Ok(UserInstruction::ShowRegisters),
            "n" => Ok(UserInstruction::SingleStep),
            s if s.starts_with("m ") => {
                let hex_address = s.trim_start_matches("m ");
                if !hex_address.starts_with("0x") {
                    return Err(UserInstructionParseError::AddressShouldStartWith0x);
                }
                let hex_address = hex_address.trim_start_matches("0x");
                let address = u64::from_str_radix(hex_address, 16).map_err(UserInstructionParseError::UnparseableAddress)?;
                Ok(UserInstruction::ShowMemory { address })
            }
            s if s.starts_with("b ") => {
                let hex_address = s.trim_start_matches("b ");
                if !hex_address.starts_with("0x") {
                    return Err(UserInstructionParseError::AddressShouldStartWith0x);
                }
                let hex_address = hex_address.trim_start_matches("0x");
                let address = u64::from_str_radix(hex_address, 16).map_err(UserInstructionParseError::UnparseableAddress)?;
                Ok(UserInstruction::AddBreakpoint { address })
            },
            s if s.starts_with("w ") => {
                let raw_values = s.trim_start_matches("w ");
                let values : Vec<&str> = raw_values.split(' ').collect();
                if values.len() < 2 {
                    return Err(UserInstructionParseError::NotEmoughArguments);
                }
                let hex_address = values[0];
                let value = values[1];

                if !hex_address.starts_with("0x") {
                    return Err(UserInstructionParseError::AddressShouldStartWith0x);
                }
                let hex_address = hex_address.trim_start_matches("0x");
                let address = u64::from_str_radix(hex_address, 16).map_err(UserInstructionParseError::UnparseableAddress)?;
                
                let value = i64::from_str_radix(value, 10).map_err(UserInstructionParseError::UnparseableValue)?;
                
                Ok(UserInstruction::WriteToMemory { address, value })
            },
            s if s.starts_with("f ") => {
                let value = s.trim_start_matches("f ");
                let value = i64::from_str_radix(value, 10).map_err(UserInstructionParseError::UnparseableValue)?;
                println!("searching for {value}");
                Ok(UserInstruction::FindInMemory { value })
            },
            _ => Err(UserInstructionParseError::UnknownInstruction)
        }
    }
}

