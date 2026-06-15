use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};

use argus_common::error::{ArgusError, Result};

#[derive(Debug, Clone)]
pub struct WasmPlugin {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub wasm_bytes: Vec<u8>,
    pub hook_points: Vec<HookPoint>,
    pub config: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HookPoint {
    OnPacketIngress,
    OnPacketEgress,
    OnRuleMatch,
    OnConnectionNew,
    OnConnectionClose,
    OnRateLimit,
    OnAlertGenerated,
    OnConfigChange,
}

#[derive(Debug, Clone)]
pub struct FlowMetadata {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: String,
    pub interface: String,
    pub rule_action: Option<String>,
    pub rule_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    pub action: PluginAction,
    pub annotations: HashMap<String, String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginAction {
    Continue,
    Redirect { reason: String },
    Alert { severity: String, message: String },
}

pub struct WasmPluginEngine {
    plugins: Mutex<HashMap<String, WasmPlugin>>,
    hooks: Mutex<HashMap<HookPoint, Vec<String>>>,
}

impl WasmPluginEngine {
    pub fn new() -> Self {
        Self {
            plugins: Mutex::new(HashMap::new()),
            hooks: Mutex::new(HashMap::new()),
        }
    }

    #[instrument(skip(self, wasm_bytes))]
    pub fn load_plugin(
        &self,
        name: &str,
        version: &str,
        description: &str,
        hook_points: Vec<HookPoint>,
        config: serde_json::Value,
        wasm_bytes: Vec<u8>,
    ) -> Result<()> {
        let validator = wasmparser::Validator::new();

        if let Err(e) = validator.validate_all(&wasm_bytes) {
            return Err(ArgusError::Validation(format!(
                "WASM validation failed: {}",
                e
            )));
        }

        let id = format!("{}/{}", name, version);
        let mut plugins = self.plugins.lock().map_err(|e| {
            ArgusError::Internal(format!("lock error: {}", e))
        })?;

        if plugins.contains_key(&id) {
            return Err(ArgusError::Validation(format!(
                "plugin {} already loaded",
                id
            )));
        }

        let plugin = WasmPlugin {
            id: id.clone(),
            name: name.to_string(),
            version: version.to_string(),
            description: description.to_string(),
            wasm_bytes,
            hook_points: hook_points.clone(),
            config,
            enabled: true,
        };

        self.register_hooks(&id, &hook_points)?;
        plugins.insert(id, plugin);

        info!("Loaded WASM plugin: {}", name);
        Ok(())
    }

    fn register_hooks(
        &self,
        plugin_id: &str,
        hook_points: &[HookPoint],
    ) -> Result<()> {
        let mut hooks = self.hooks.lock().map_err(|e| {
            ArgusError::Internal(format!("lock error: {}", e))
        })?;

        for hp in hook_points {
            hooks
                .entry(hp.clone())
                .or_insert_with(Vec::new)
                .push(plugin_id.to_string());
        }

        Ok(())
    }

    #[instrument(skip(self, metadata))]
    pub fn run_hook(
        &self,
        hook_point: HookPoint,
        metadata: &FlowMetadata,
    ) -> Vec<PluginOutput> {
        let hooks = match self.hooks.lock() {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        let plugin_ids = match hooks.get(&hook_point) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        let plugins = match self.plugins.lock() {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        let mut outputs = Vec::new();

        for plugin_id in &plugin_ids {
            if let Some(plugin) = plugins.get(plugin_id) {
                if !plugin.enabled {
                    continue;
                }

                match self.execute_plugin(plugin, metadata) {
                    Ok(output) => outputs.push(output),
                    Err(e) => {
                        error!(
                            plugin = %plugin.name,
                            error = %e,
                            "WASM plugin execution failed"
                        );
                    }
                }
            }
        }

        outputs
    }

    fn execute_plugin(
        &self,
        plugin: &WasmPlugin,
        metadata: &FlowMetadata,
    ) -> Result<PluginOutput> {
        let engine = wasmtime::Engine::new(&wasmtime::Config::new()
            .epoch_interruption(true)
            .cranelift_nan_canonicalization(true)
            .consume_fuel(true))
            .map_err(|e| ArgusError::Internal(format!("wasmtime engine: {}", e)))?;

        let mut store = wasmtime::Store::new(&engine, ());

        store.set_fuel(100_000).map_err(|e| {
            ArgusError::Internal(format!("fuel limit: {}", e))
        })?;

        let module = wasmtime::Module::new(&engine, &plugin.wasm_bytes).map_err(|e| {
            ArgusError::Validation(format!("WASM module compile: {}", e))
        })?;

        let metadata_json = serde_json::to_vec(metadata)
            .map_err(|e| ArgusError::Serialization(format!("metadata serialization: {}", e)))?;
        let config_json = serde_json::to_vec(&plugin.config)
            .map_err(|e| ArgusError::Serialization(format!("config serialization: {}", e)))?;

        let mut linker = wasmtime::Linker::new(&engine);

        let _result: Vec<u8> = Vec::new();

        linker
            .func_wrap("env", "log", |msg_ptr: i32, msg_len: i32| {
                println!("WASM plugin log");
            })
            .map_err(|e| ArgusError::Internal(format!("linker setup: {}", e)))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| ArgusError::External(format!("WASM instantiate: {}", e)))?;

        if let Some(process_fn) = instance.get_typed_func::<(i32, i32), i32>(&mut store, "process")
            .ok()
        {
            let _ = process_fn.call(&mut store, (0, 0)).map_err(|e| {
                ArgusError::External(format!("WASM call: {}", e))
            })?;
        }

        Ok(PluginOutput {
            action: PluginAction::Continue,
            annotations: HashMap::new(),
            tags: Vec::new(),
        })
    }

    pub fn unload_plugin(&self, plugin_id: &str) -> Result<()> {
        let mut plugins = self.plugins.lock().map_err(|e| {
            ArgusError::Internal(format!("lock error: {}", e))
        })?;

        let plugin = plugins.remove(plugin_id).ok_or_else(|| {
            ArgusError::NotFound(format!("plugin {} not found", plugin_id))
        })?;

        let mut hooks = self.hooks.lock().map_err(|e| {
            ArgusError::Internal(format!("lock error: {}", e))
        })?;

        for hp in &plugin.hook_points {
            if let Some(ids) = hooks.get_mut(hp) {
                ids.retain(|id| id != plugin_id);
            }
        }

        info!("Unloaded WASM plugin: {}", plugin.name);
        Ok(())
    }

    pub fn list_plugins(&self) -> Vec<WasmPlugin> {
        self.plugins
            .lock()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for WasmPluginEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_lifecycle() {
        let engine = WasmPluginEngine::new();

        let wasm_bytes = b"\x00asm\x01\x00\x00\x00".to_vec();

        let result = engine.load_plugin(
            "test-plugin",
            "0.1.0",
            "Test plugin",
            vec![HookPoint::OnPacketIngress],
            serde_json::json!({"threshold": 100}),
            wasm_bytes,
        );

        assert!(result.is_err());

        let plugins = engine.list_plugins();
        assert!(plugins.is_empty());
    }

    #[test]
    fn test_plugin_unload() {
        let engine = WasmPluginEngine::new();
        let result = engine.unload_plugin("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_hook_registration() {
        let engine = WasmPluginEngine::new();
        let result = engine.register_hooks("test/v1", &[HookPoint::OnRuleMatch, HookPoint::OnAlertGenerated]);
        assert!(result.is_ok());
    }
}
