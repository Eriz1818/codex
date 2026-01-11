use super::HookNotification;
use serde_json::Value;

pub(crate) fn map_tool_name(tool_name: &str) -> Option<String> {
    match tool_name {
        "shell"
        | "shell_command"
        | "exec_command"
        | "write_stdin"
        | "read_process_output"
        | "start_process"
        | "interact_with_process" => Some("Bash".to_string()),
        "read_file" | "read_multiple_files" | "read_mcp_resource" => Some("Read".to_string()),
        "write_file" => Some("Write".to_string()),
        "apply_patch" | "edit_block" => Some("Edit".to_string()),
        "list_directory" => Some("Glob".to_string()),
        "start_search" => Some("Grep".to_string()),
        _ if tool_name.starts_with("mcp__") => Some("MCP".to_string()),
        _ => None,
    }
}

pub(crate) fn default_hook_event_name(notification: &HookNotification) -> Option<&'static str> {
    match notification {
        HookNotification::SessionStart { .. } => Some("SessionStart"),
        HookNotification::SessionEnd { .. } => Some("SessionEnd"),
        HookNotification::UserPromptSubmit { .. } => Some("UserPromptSubmit"),
        HookNotification::PreCompact { .. } => Some("PreCompact"),
        HookNotification::Notification { .. } => Some("Notification"),
        HookNotification::SubagentStop { .. } => Some("SubagentStop"),
        HookNotification::AgentTurnComplete { .. } => Some("Stop"),
        HookNotification::ApprovalRequested { .. } => Some("PermissionRequest"),
        HookNotification::ToolCallStarted { .. } => Some("PreToolUse"),
        HookNotification::ToolCallFinished { .. } => Some("PostToolUse"),
        _ => None,
    }
}

pub(crate) fn translate_tool_input(
    tool_name: Option<&str>,
    tool_input: Option<&Value>,
) -> Option<Value> {
    let Some(tool_name) = tool_name else {
        return tool_input.cloned();
    };
    let tool_input = tool_input?;

    match tool_name {
        "Write" => translate_tool_input_write(tool_input),
        "Edit" => translate_tool_input_edit(tool_input),
        "Read" => translate_tool_input_read(tool_input),
        "Bash" => translate_tool_input_bash(tool_input),
        _ => Some(tool_input.clone()),
    }
}

pub(crate) fn translate_tool_response(
    tool_name: Option<&str>,
    tool_response: Option<&Value>,
) -> Option<Value> {
    let tool_response = tool_response?;

    match tool_name {
        Some("Bash") => translate_tool_response_bash(tool_response),
        _ => Some(tool_response.clone()),
    }
}

fn translate_tool_input_write(tool_input: &Value) -> Option<Value> {
    let obj = tool_input.as_object()?;
    let path = obj
        .get("file_path")
        .or_else(|| obj.get("path"))
        .and_then(Value::as_str)?;

    let content = obj.get("content").and_then(Value::as_str);
    Some(match content {
        Some(content) => serde_json::json!({ "file_path": path, "content": content }),
        None => serde_json::json!({ "file_path": path }),
    })
}

fn translate_tool_input_read(tool_input: &Value) -> Option<Value> {
    let obj = tool_input.as_object()?;
    let path = obj
        .get("file_path")
        .or_else(|| obj.get("path"))
        .and_then(Value::as_str)?;

    let mut out = serde_json::Map::new();
    out.insert("file_path".to_string(), Value::String(path.to_string()));
    if let Some(offset) = obj.get("offset") {
        out.insert("offset".to_string(), offset.clone());
    }
    if let Some(length) = obj.get("length") {
        out.insert("length".to_string(), length.clone());
    }
    Some(Value::Object(out))
}

fn translate_tool_input_edit(tool_input: &Value) -> Option<Value> {
    let obj = tool_input.as_object()?;
    let file_path = obj
        .get("file_path")
        .or_else(|| obj.get("path"))
        .and_then(Value::as_str)
        .or_else(|| file_path_from_apply_patch(obj.get("patch")?.as_str()?));

    file_path.map(|file_path| serde_json::json!({ "file_path": file_path }))
}

fn translate_tool_input_bash(tool_input: &Value) -> Option<Value> {
    let obj = tool_input.as_object()?;
    let command = obj
        .get("command")
        .or_else(|| obj.get("cmd"))
        .and_then(Value::as_str)?;
    Some(serde_json::json!({ "command": command }))
}

fn translate_tool_response_bash(tool_response: &Value) -> Option<Value> {
    if tool_response.is_string() {
        return Some(serde_json::json!({ "stdout": tool_response }));
    }

    let obj = tool_response.as_object()?;
    if obj.contains_key("stdout") || obj.contains_key("stderr") {
        return Some(tool_response.clone());
    }

    Some(serde_json::json!({ "stdout": tool_response }))
}

fn file_path_from_apply_patch(patch: &str) -> Option<&str> {
    for line in patch.lines() {
        let line = line.strip_prefix("*** ")?;
        if let Some(path) = line.strip_prefix("Update File: ") {
            return Some(path.trim());
        }
        if let Some(path) = line.strip_prefix("Add File: ") {
            return Some(path.trim());
        }
        if let Some(path) = line.strip_prefix("Delete File: ") {
            return Some(path.trim());
        }
    }
    None
}
