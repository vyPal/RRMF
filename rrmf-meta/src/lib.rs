use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub format_version: u32,
    #[serde(default)]
    pub crate_filter: Vec<String>,
    pub build_id: Option<String>,
    pub pie: bool,
    pub image_base: u64,
    pub functions: Vec<Function>,
    pub types: Vec<TypeLayout>,
    #[serde(default)]
    pub variables: Vec<Variable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub linkage_name: Option<String>,
    pub address: u64,
    pub size: Option<u64>,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub linkage_name: Option<String>,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub inlined_at: Vec<u64>,
    #[serde(default)]
    pub params: Vec<Param>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub type_name: String,
    pub size: Option<u64>,
    pub entry_reg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeLayout {
    pub name: String,
    pub size: u64,
    pub align: Option<u64>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub type_name: String,
    pub kind: ScalarKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScalarKind {
    Signed,
    Unsigned,
    Float,
    Bool,
    Pointer,
    Other,
}

impl Metadata {
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        Ok(fs::write(path, serde_json::to_vec(self)?)?)
    }

    pub fn path_for_bin(bin: &Path) -> PathBuf {
        let mut s = bin.as_os_str().to_owned();
        s.push(".rrmf.json");
        s.into()
    }

    pub fn function_index(&self) -> HashMap<&str, Vec<&Function>> {
        let mut m: HashMap<&str, Vec<&Function>> = HashMap::new();
        for f in &self.functions {
            m.entry(f.name.as_str()).or_default().push(f);
        }
        m
    }

    pub fn type_by_name(&self, name: &str) -> Option<&TypeLayout> {
        self.types.iter().find(|t| t.name == name)
    }

    pub fn variable_by_name(&self, name: &str) -> Option<&Variable> {
        self.variables.iter().find(|v| v.name == name).or_else(|| {
            self.variables
                .iter()
                .find(|v| v.linkage_name.as_deref() == Some(name))
        })
    }
}
