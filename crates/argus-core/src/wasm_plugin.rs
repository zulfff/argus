use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Serialize)]
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
        let mut validator = wasmparser::Validator::new();

        if let Err(e) = validator.validate_all(&wasm_bytes) {
            return Err(ArgusError::Validation(format!(
                "WASM validation failed: {}",
                e
            )));
        }

        let id = format!("{}/{}", name, version);
        let mut plugins = self
            .plugins
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

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

    fn register_hooks(&self, plugin_id: &str, hook_points: &[HookPoint]) -> Result<()> {
        let mut hooks = self
            .hooks
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        for hp in hook_points {
            hooks
                .entry(hp.clone())
                .or_insert_with(Vec::new)
                .push(plugin_id.to_string());
        }

        Ok(())
    }

    #[instrument(skip(self, metadata))]
    pub fn run_hook(&self, hook_point: HookPoint, metadata: &FlowMetadata) -> Vec<PluginOutput> {
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

    fn execute_plugin(&self, plugin: &WasmPlugin, metadata: &FlowMetadata) -> Result<PluginOutput> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        // ponytail: epoch_interruption would add infinite-loop protection but
        // requires periodic Engine::increment_epoch() calls from a background
        // thread — enable when adding a global epoch ticker.
        let engine = wasmtime::Engine::new(&config)
        .map_err(|e| ArgusError::Internal(format!("wasmtime engine: {}", e)))?;

        let mut store = wasmtime::Store::new(&engine, ());

        store
            .set_fuel(100_000)
            .map_err(|e| ArgusError::Internal(format!("fuel limit: {}", e)))?;

        let module = wasmtime::Module::new(&engine, &plugin.wasm_bytes)
            .map_err(|e| ArgusError::Validation(format!("WASM module compile: {}", e)))?;

        let metadata_json =
            serde_json::to_vec(metadata).map_err(ArgusError::Serialization)?;
        let _config_json =
            serde_json::to_vec(&plugin.config).map_err(ArgusError::Serialization)?;

        let mut linker = wasmtime::Linker::new(&engine);

        linker
            .func_wrap(
                "env",
                "log",
                |mut caller: wasmtime::Caller<'_, ()>, msg_ptr: i32, msg_len: i32| {
                    if msg_len <= 0 || msg_ptr < 0 {
                        return;
                    }
                    let Some(mem) = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                    else {
                        return;
                    };
                    let mut buf = vec![0u8; msg_len as usize];
                    if mem.read(&caller, msg_ptr as usize, &mut buf).is_err() {
                        return;
                    }
                    if let Ok(s) = std::str::from_utf8(&buf) {
                        tracing::info!(target: "wasm_plugin", "{}", s);
                    }
                },
            )
            .map_err(|e| ArgusError::Internal(format!("linker setup: {}", e)))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| ArgusError::External(format!("WASM instantiate: {}", e)))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| {
                ArgusError::Validation("WASM plugin must export 'memory'".into())
            })?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| {
                ArgusError::Validation("WASM plugin must export 'alloc(i32) -> i32'".into())
            })?;

        let process_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "process")
            .map_err(|_| {
                ArgusError::Validation(
                    "WASM plugin must export 'process(i32, i32) -> i32'".into(),
                )
            })?;

        let mdata_len = metadata_json.len() as i32;
        let mdata_ptr = if mdata_len > 0 {
            let ptr = alloc_fn
                .call(&mut store, mdata_len)
                .map_err(|e| ArgusError::External(format!("WASM alloc failed: {}", e)))?;
            memory
                .write(&mut store, ptr as usize, &metadata_json)
                .map_err(|e| ArgusError::External(format!("memory write: {}", e)))?;
            ptr
        } else {
            0
        };

        let result_code = process_fn
            .call(&mut store, (mdata_ptr, mdata_len))
            .map_err(|e| ArgusError::External(format!("WASM process failed: {}", e)))?;

        let output = match result_code {
            0 => PluginOutput {
                action: PluginAction::Continue,
                annotations: HashMap::new(),
                tags: Vec::new(),
            },
            1 => PluginOutput {
                action: PluginAction::Redirect {
                    reason: format!("plugin '{}' redirected", plugin.name),
                },
                annotations: HashMap::new(),
                tags: Vec::new(),
            },
            2 => PluginOutput {
                action: PluginAction::Alert {
                    severity: "warning".into(),
                    message: format!("plugin '{}' raised alert", plugin.name),
                },
                annotations: HashMap::new(),
                tags: Vec::new(),
            },
            code => {
                tracing::warn!(plugin=%plugin.name, code, "unknown WASM return code");
                PluginOutput {
                    action: PluginAction::Continue,
                    annotations: HashMap::new(),
                    tags: Vec::new(),
                }
            }
        };

        Ok(output)
    }

    pub fn unload_plugin(&self, plugin_id: &str) -> Result<()> {
        let mut plugins = self
            .plugins
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

        let plugin = plugins
            .remove(plugin_id)
            .ok_or_else(|| ArgusError::NotFound(format!("plugin {} not found", plugin_id)))?;

        let mut hooks = self
            .hooks
            .lock()
            .map_err(|e| ArgusError::Internal(format!("lock error: {}", e)))?;

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

        let wasm_bytes = b"\x00asm\x01\x00\x00\x00\xff".to_vec();

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
        let result = engine.register_hooks(
            "test/v1",
            &[HookPoint::OnRuleMatch, HookPoint::OnAlertGenerated],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_wasm_plugin_end_to_end_real_module() {
        let wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    i32.const 2048
  )
  (func (export "process") (param i32 i32) (result i32)
    i32.const 2
  )
)
"#;
        let wasm_bytes = wat::parse_str(wat).expect("WAT compilation failed");

        let engine = WasmPluginEngine::new();
        engine
            .load_plugin(
                "end-to-end-test",
                "1.0.0",
                "End-to-end test plugin",
                vec![HookPoint::OnConnectionNew],
                serde_json::json!({"threshold": 100}),
                wasm_bytes,
            )
            .expect("plugin load failed");

        let metadata = FlowMetadata {
            src_ip: "10.0.0.1".into(),
            dst_ip: "8.8.8.8".into(),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            direction: "outbound".into(),
            interface: "eth0".into(),
            rule_action: None,
            rule_id: None,
            timestamp: chrono::Utc::now(),
            tags: HashMap::new(),
        };

        let outputs = engine.run_hook(HookPoint::OnConnectionNew, &metadata);
        assert!(!outputs.is_empty(), "expected at least one plugin output");
        assert!(
            matches!(outputs[0].action, PluginAction::Alert { .. }),
            "expected Alert action, got: {:?}",
            outputs[0].action
        );

        let plugins = engine.list_plugins();
        assert_eq!(plugins.len(), 1);

        engine
            .unload_plugin("end-to-end-test/1.0.0")
            .expect("plugin unload failed");
        assert!(engine.list_plugins().is_empty());
    }
}
