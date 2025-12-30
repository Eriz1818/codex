use crate::client_common::tools::ToolSpec;
use crate::context_manager::estimate_reasoning_length;
use crate::error::Result;
use crate::models_manager::model_family::ModelFamily;
use crate::truncate::approx_token_count;
pub use codex_api::common::ResponseEvent;
use codex_apply_patch::APPLY_PATCH_TOOL_INSTRUCTIONS;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputContentItem;
use codex_protocol::models::LocalShellAction;
use codex_protocol::models::ResponseItem;
use codex_protocol::models::WebSearchAction;
use futures::Stream;
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::Deref;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::sync::mpsc;

/// Review thread system prompt. Edit `core/src/review_prompt.md` to customize.
pub const REVIEW_PROMPT: &str = include_str!("../review_prompt.md");

// Centralized templates for review-related user messages
pub const REVIEW_EXIT_SUCCESS_TMPL: &str = include_str!("../templates/review/exit_success.xml");
pub const REVIEW_EXIT_INTERRUPTED_TMPL: &str =
    include_str!("../templates/review/exit_interrupted.xml");

/// API request payload for a single model turn
#[derive(Default, Debug, Clone)]
pub struct Prompt {
    /// Conversation context input items.
    pub input: Vec<ResponseItem>,

    /// Tools available to the model, including additional tools sourced from
    /// external MCP servers.
    pub(crate) tools: Vec<ToolSpec>,

    /// Whether parallel tool calls are permitted for this prompt.
    pub(crate) parallel_tool_calls: bool,

    /// Optional override for the built-in BASE_INSTRUCTIONS.
    pub base_instructions_override: Option<String>,

    /// Optional the output schema for the model's response.
    pub output_schema: Option<Value>,
}

impl Prompt {
    pub(crate) fn get_full_instructions<'a>(&'a self, model: &'a ModelFamily) -> Cow<'a, str> {
        let base = self
            .base_instructions_override
            .as_deref()
            .unwrap_or(model.base_instructions.deref());
        // When there are no custom instructions, add apply_patch_tool_instructions if:
        // - the model needs special instructions (4.1)
        // AND
        // - there is no apply_patch tool present
        let is_apply_patch_tool_present = self.tools.iter().any(|tool| match tool {
            ToolSpec::Function(f) => f.name == "apply_patch",
            ToolSpec::Freeform(f) => f.name == "apply_patch",
            _ => false,
        });
        if self.base_instructions_override.is_none()
            && model.needs_special_apply_patch_instructions
            && !is_apply_patch_tool_present
        {
            Cow::Owned(format!("{base}\n{APPLY_PATCH_TOOL_INSTRUCTIONS}"))
        } else {
            Cow::Borrowed(base)
        }
    }

    pub(crate) fn get_formatted_input(&self) -> Vec<ResponseItem> {
        let mut input = self.input.clone();

        // when using the *Freeform* apply_patch tool specifically, tool outputs
        // should be structured text, not json. Do NOT reserialize when using
        // the Function tool - note that this differs from the check above for
        // instructions. We declare the result as a named variable for clarity.
        let is_freeform_apply_patch_tool_present = self.tools.iter().any(|tool| match tool {
            ToolSpec::Freeform(f) => f.name == "apply_patch",
            _ => false,
        });
        if is_freeform_apply_patch_tool_present {
            reserialize_shell_outputs(&mut input);
        }

        input
    }

    pub(crate) fn estimate_token_count(&self, model: &ModelFamily) -> i64 {
        let instructions = self.get_full_instructions(model);
        let instructions_tokens =
            i64::try_from(approx_token_count(instructions.as_ref())).unwrap_or(i64::MAX);

        // IMPORTANT: this is a heuristic. Prefer counting the actual text fields that are
        // semantically visible to the model instead of serializing entire ResponseItems to JSON,
        // which can drastically overestimate due to structural keys.
        //
        // NOTE: encrypted reasoning uses `estimate_reasoning_length` (decoded bytes after overhead)
        // and is intentionally over-counted versus tokens to keep auto-compact decisions
        // conservative.
        let estimate_item_tokens = |item: &ResponseItem| -> i64 {
            let estimate_str_tokens =
                |text: &str| -> i64 { i64::try_from(approx_token_count(text)).unwrap_or(i64::MAX) };
            let estimate_content_item_tokens = |content: &ContentItem| -> i64 {
                match content {
                    ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                        estimate_str_tokens(text)
                    }
                    ContentItem::InputImage { image_url } => estimate_str_tokens(image_url),
                }
            };
            let estimate_fco_item_tokens = |content: &FunctionCallOutputContentItem| -> i64 {
                match content {
                    FunctionCallOutputContentItem::InputText { text } => estimate_str_tokens(text),
                    FunctionCallOutputContentItem::InputImage { image_url } => {
                        estimate_str_tokens(image_url)
                    }
                }
            };

            match item {
                ResponseItem::GhostSnapshot { .. } => 0,
                ResponseItem::Reasoning {
                    encrypted_content: Some(content),
                    ..
                }
                | ResponseItem::Compaction {
                    encrypted_content: content,
                } => estimate_reasoning_length(content.len()) as i64,
                ResponseItem::Message { role, content, .. } => estimate_str_tokens(role)
                    .saturating_add(content.iter().fold(0i64, |acc, item| {
                        acc.saturating_add(estimate_content_item_tokens(item))
                    })),
                ResponseItem::FunctionCall {
                    name, arguments, ..
                } => estimate_str_tokens(name).saturating_add(estimate_str_tokens(arguments)),
                ResponseItem::FunctionCallOutput { output, .. } => {
                    if let Some(items) = output.content_items.as_ref() {
                        items.iter().fold(0i64, |acc, item| {
                            acc.saturating_add(estimate_fco_item_tokens(item))
                        })
                    } else {
                        estimate_str_tokens(&output.content)
                    }
                }
                ResponseItem::CustomToolCall { name, input, .. } => {
                    estimate_str_tokens(name).saturating_add(estimate_str_tokens(input))
                }
                ResponseItem::CustomToolCallOutput { output, .. } => estimate_str_tokens(output),
                ResponseItem::LocalShellCall { action, .. } => match action {
                    LocalShellAction::Exec(exec) => {
                        let command = exec.command.join(" ");
                        let mut total = estimate_str_tokens(&command);
                        if let Some(working_directory) = exec.working_directory.as_ref() {
                            total = total.saturating_add(estimate_str_tokens(working_directory));
                        }
                        if let Some(user) = exec.user.as_ref() {
                            total = total.saturating_add(estimate_str_tokens(user));
                        }
                        if let Some(env) = exec.env.as_ref() {
                            total = env.iter().fold(total, |acc, (k, v)| {
                                acc.saturating_add(estimate_str_tokens(k))
                                    .saturating_add(estimate_str_tokens(v))
                            });
                        }
                        total
                    }
                },
                ResponseItem::WebSearchCall { action, .. } => match action {
                    WebSearchAction::Search { query } => {
                        query.as_ref().map_or(0, |query| estimate_str_tokens(query))
                    }
                    WebSearchAction::OpenPage { url } => {
                        url.as_ref().map_or(0, |url| estimate_str_tokens(url))
                    }
                    WebSearchAction::FindInPage { url, pattern } => url
                        .as_ref()
                        .map_or(0, |url| estimate_str_tokens(url))
                        .saturating_add(
                            pattern
                                .as_ref()
                                .map_or(0, |pattern| estimate_str_tokens(pattern)),
                        ),
                    WebSearchAction::Other => 0,
                },
                ResponseItem::Reasoning { .. } => 0,
                ResponseItem::Other => 0,
            }
        };

        let formatted_input = self.get_formatted_input();
        let last_user_message_index = formatted_input
            .iter()
            .rposition(|item| matches!(item, ResponseItem::Message { role, .. } if role == "user"));

        let input_tokens = formatted_input
            .iter()
            .enumerate()
            .fold(0i64, |acc, (idx, item)| {
                let should_count_reasoning = last_user_message_index
                    .map(|last_user| idx < last_user)
                    .unwrap_or(true);
                acc.saturating_add(match item {
                    ResponseItem::Reasoning {
                        encrypted_content: Some(content),
                        ..
                    } if should_count_reasoning => estimate_reasoning_length(content.len()) as i64,
                    ResponseItem::Reasoning { .. } => 0,
                    _ => estimate_item_tokens(item),
                })
            });

        let tools_tokens = if self.tools.is_empty() {
            0
        } else {
            match serde_json::to_string(&self.tools) {
                Ok(serialized) => {
                    i64::try_from(approx_token_count(&serialized)).unwrap_or(i64::MAX)
                }
                Err(_) => i64::MAX,
            }
        };

        let schema_tokens =
            self.output_schema
                .as_ref()
                .map_or(0, |schema| match serde_json::to_string(schema) {
                    Ok(serialized) => {
                        i64::try_from(approx_token_count(&serialized)).unwrap_or(i64::MAX)
                    }
                    Err(_) => i64::MAX,
                });

        instructions_tokens
            .saturating_add(input_tokens)
            .saturating_add(tools_tokens)
            .saturating_add(schema_tokens)
    }
}

fn reserialize_shell_outputs(items: &mut [ResponseItem]) {
    let mut shell_call_ids: HashSet<String> = HashSet::new();

    items.iter_mut().for_each(|item| match item {
        ResponseItem::LocalShellCall { call_id, id, .. } => {
            if let Some(identifier) = call_id.clone().or_else(|| id.clone()) {
                shell_call_ids.insert(identifier);
            }
        }
        ResponseItem::CustomToolCall {
            id: _,
            status: _,
            call_id,
            name,
            input: _,
        } => {
            if name == "apply_patch" {
                shell_call_ids.insert(call_id.clone());
            }
        }
        ResponseItem::CustomToolCallOutput { call_id, output } => {
            if shell_call_ids.remove(call_id)
                && let Some(structured) = parse_structured_shell_output(output)
            {
                *output = structured
            }
        }
        ResponseItem::FunctionCall { name, call_id, .. }
            if is_shell_tool_name(name) || name == "apply_patch" =>
        {
            shell_call_ids.insert(call_id.clone());
        }
        ResponseItem::FunctionCallOutput { call_id, output } => {
            if shell_call_ids.remove(call_id)
                && let Some(structured) = parse_structured_shell_output(&output.content)
            {
                output.content = structured
            }
        }
        _ => {}
    })
}

fn is_shell_tool_name(name: &str) -> bool {
    matches!(name, "shell" | "container.exec")
}

#[derive(Deserialize)]
struct ExecOutputJson {
    output: String,
    metadata: ExecOutputMetadataJson,
}

#[derive(Deserialize)]
struct ExecOutputMetadataJson {
    exit_code: i32,
    duration_seconds: f32,
}

fn parse_structured_shell_output(raw: &str) -> Option<String> {
    let parsed: ExecOutputJson = serde_json::from_str(raw).ok()?;
    Some(build_structured_output(&parsed))
}

fn build_structured_output(parsed: &ExecOutputJson) -> String {
    let mut sections = Vec::new();
    sections.push(format!("Exit code: {}", parsed.metadata.exit_code));
    sections.push(format!(
        "Wall time: {} seconds",
        parsed.metadata.duration_seconds
    ));

    let mut output = parsed.output.clone();
    if let Some((stripped, total_lines)) = strip_total_output_header(&parsed.output) {
        sections.push(format!("Total output lines: {total_lines}"));
        output = stripped.to_string();
    }

    sections.push("Output:".to_string());
    sections.push(output);

    sections.join("\n")
}

fn strip_total_output_header(output: &str) -> Option<(&str, u32)> {
    let after_prefix = output.strip_prefix("Total output lines: ")?;
    let (total_segment, remainder) = after_prefix.split_once('\n')?;
    let total_lines = total_segment.parse::<u32>().ok()?;
    let remainder = remainder.strip_prefix('\n').unwrap_or(remainder);
    Some((remainder, total_lines))
}

pub(crate) mod tools {
    use crate::tools::spec::JsonSchema;
    use serde::Deserialize;
    use serde::Serialize;

    /// When serialized as JSON, this produces a valid "Tool" in the OpenAI
    /// Responses API.
    #[derive(Debug, Clone, Serialize, PartialEq)]
    #[serde(tag = "type")]
    pub(crate) enum ToolSpec {
        #[serde(rename = "function")]
        Function(ResponsesApiTool),
        #[serde(rename = "local_shell")]
        LocalShell {},
        // TODO: Understand why we get an error on web_search although the API docs say it's supported.
        // https://platform.openai.com/docs/guides/tools-web-search?api-mode=responses#:~:text=%7B%20type%3A%20%22web_search%22%20%7D%2C
        #[serde(rename = "web_search")]
        WebSearch {},
        #[serde(rename = "custom")]
        Freeform(FreeformTool),
    }

    impl ToolSpec {
        pub(crate) fn name(&self) -> &str {
            match self {
                ToolSpec::Function(tool) => tool.name.as_str(),
                ToolSpec::LocalShell {} => "local_shell",
                ToolSpec::WebSearch {} => "web_search",
                ToolSpec::Freeform(tool) => tool.name.as_str(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct FreeformTool {
        pub(crate) name: String,
        pub(crate) description: String,
        pub(crate) format: FreeformToolFormat,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct FreeformToolFormat {
        pub(crate) r#type: String,
        pub(crate) syntax: String,
        pub(crate) definition: String,
    }

    #[derive(Debug, Clone, Serialize, PartialEq)]
    pub struct ResponsesApiTool {
        pub(crate) name: String,
        pub(crate) description: String,
        /// TODO: Validation. When strict is set to true, the JSON schema,
        /// `required` and `additional_properties` must be present. All fields in
        /// `properties` must be present in `required`.
        pub(crate) strict: bool,
        pub(crate) parameters: JsonSchema,
    }
}

pub struct ResponseStream {
    pub(crate) rx_event: mpsc::Receiver<Result<ResponseEvent>>,
}

impl Stream for ResponseStream {
    type Item = Result<ResponseEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx_event.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use codex_api::ResponsesApiRequest;
    use codex_api::common::OpenAiVerbosity;
    use codex_api::common::TextControls;
    use codex_api::create_text_param_for_request;
    use pretty_assertions::assert_eq;

    use crate::config::test_config;
    use crate::models_manager::manager::ModelsManager;

    use super::*;

    struct InstructionsTestCase {
        pub slug: &'static str,
        pub expects_apply_patch_instructions: bool,
    }
    #[test]
    fn get_full_instructions_no_user_content() {
        let prompt = Prompt {
            ..Default::default()
        };
        let test_cases = vec![
            InstructionsTestCase {
                slug: "gpt-3.5",
                expects_apply_patch_instructions: true,
            },
            InstructionsTestCase {
                slug: "gpt-4.1",
                expects_apply_patch_instructions: true,
            },
            InstructionsTestCase {
                slug: "gpt-4o",
                expects_apply_patch_instructions: true,
            },
            InstructionsTestCase {
                slug: "gpt-5",
                expects_apply_patch_instructions: true,
            },
            InstructionsTestCase {
                slug: "gpt-5.1",
                expects_apply_patch_instructions: false,
            },
            InstructionsTestCase {
                slug: "codex-mini-latest",
                expects_apply_patch_instructions: true,
            },
            InstructionsTestCase {
                slug: "gpt-oss:120b",
                expects_apply_patch_instructions: false,
            },
            InstructionsTestCase {
                slug: "gpt-5.1-codex",
                expects_apply_patch_instructions: false,
            },
            InstructionsTestCase {
                slug: "gpt-5.1-codex-max",
                expects_apply_patch_instructions: false,
            },
        ];
        for test_case in test_cases {
            let config = test_config();
            let model_family =
                ModelsManager::construct_model_family_offline(test_case.slug, &config);
            let expected = if test_case.expects_apply_patch_instructions {
                format!(
                    "{}\n{}",
                    model_family.clone().base_instructions,
                    APPLY_PATCH_TOOL_INSTRUCTIONS
                )
            } else {
                model_family.clone().base_instructions
            };

            let full = prompt.get_full_instructions(&model_family);
            assert_eq!(full, expected);
        }
    }

    #[test]
    fn serializes_text_verbosity_when_set() {
        let input: Vec<ResponseItem> = vec![];
        let tools: Vec<serde_json::Value> = vec![];
        let req = ResponsesApiRequest {
            model: "gpt-5.1",
            instructions: "i",
            input: &input,
            tools: &tools,
            tool_choice: "auto",
            parallel_tool_calls: true,
            reasoning: None,
            store: false,
            stream: true,
            include: vec![],
            prompt_cache_key: None,
            text: Some(TextControls {
                verbosity: Some(OpenAiVerbosity::Low),
                format: None,
            }),
        };

        let v = serde_json::to_value(&req).expect("json");
        assert_eq!(
            v.get("text")
                .and_then(|t| t.get("verbosity"))
                .and_then(|s| s.as_str()),
            Some("low")
        );
    }

    #[test]
    fn serializes_text_schema_with_strict_format() {
        let input: Vec<ResponseItem> = vec![];
        let tools: Vec<serde_json::Value> = vec![];
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "answer": {"type": "string"}
            },
            "required": ["answer"],
        });
        let text_controls =
            create_text_param_for_request(None, &Some(schema.clone())).expect("text controls");

        let req = ResponsesApiRequest {
            model: "gpt-5.1",
            instructions: "i",
            input: &input,
            tools: &tools,
            tool_choice: "auto",
            parallel_tool_calls: true,
            reasoning: None,
            store: false,
            stream: true,
            include: vec![],
            prompt_cache_key: None,
            text: Some(text_controls),
        };

        let v = serde_json::to_value(&req).expect("json");
        let text = v.get("text").expect("text field");
        assert!(text.get("verbosity").is_none());
        let format = text.get("format").expect("format field");

        assert_eq!(
            format.get("name"),
            Some(&serde_json::Value::String("codex_output_schema".into()))
        );
        assert_eq!(
            format.get("type"),
            Some(&serde_json::Value::String("json_schema".into()))
        );
        assert_eq!(format.get("strict"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(format.get("schema"), Some(&schema));
    }

    #[test]
    fn omits_text_when_not_set() {
        let input: Vec<ResponseItem> = vec![];
        let tools: Vec<serde_json::Value> = vec![];
        let req = ResponsesApiRequest {
            model: "gpt-5.1",
            instructions: "i",
            input: &input,
            tools: &tools,
            tool_choice: "auto",
            parallel_tool_calls: true,
            reasoning: None,
            store: false,
            stream: true,
            include: vec![],
            prompt_cache_key: None,
            text: None,
        };

        let v = serde_json::to_value(&req).expect("json");
        assert!(v.get("text").is_none());
    }

    #[test]
    fn estimate_token_count_includes_tool_specs() {
        let config = test_config();
        let model_family = ModelsManager::construct_model_family_offline("gpt-4.1", &config);

        let prompt_without = Prompt::default();

        let prompt_with = Prompt {
            tools: vec![ToolSpec::Freeform(tools::FreeformTool {
                name: "example_tool".to_string(),
                description: "Example tool with a large definition".to_string(),
                format: tools::FreeformToolFormat {
                    r#type: "grammar".to_string(),
                    syntax: "lark".to_string(),
                    definition: "x".repeat(4096),
                },
            })],
            ..Default::default()
        };

        assert!(
            prompt_with.estimate_token_count(&model_family)
                > prompt_without.estimate_token_count(&model_family)
        );
    }
}
