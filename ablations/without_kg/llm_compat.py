"""Compatibility helpers for structured Qwen3 inference on older vLLM releases."""

from __future__ import annotations


def historical_llm_chat(llm, conversations, sampling_params, use_tqdm: bool = True):
    """Use the exact native vLLM chat path from the original KG run."""
    return llm.chat(
        conversations,
        sampling_params=sampling_params,
        use_tqdm=use_tqdm,
    )


def _with_no_think_control(conversation: list[dict]) -> list[dict]:
    messages = [dict(message) for message in conversation]
    for message in reversed(messages):
        if message.get("role") == "user":
            message["content"] = f"{str(message.get('content', '')).rstrip()}\n/no_think"
            break
    return messages


def llm_chat(
    llm,
    conversations,
    sampling_params,
    use_tqdm: bool = True,
    enable_thinking: bool = True,
):
    """Render prompts explicitly while preserving historical Qwen3 thinking mode."""
    tokenizer = llm.get_tokenizer()
    prompts = []
    for conversation in conversations:
        try:
            prompt = tokenizer.apply_chat_template(
                conversation,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=enable_thinking,
            )
        except TypeError:
            prompt = tokenizer.apply_chat_template(
                conversation if enable_thinking else _with_no_think_control(conversation),
                tokenize=False,
                add_generation_prompt=True,
            )
        prompts.append(prompt)
    return llm.generate(
        prompts,
        sampling_params=sampling_params,
        use_tqdm=use_tqdm,
    )
