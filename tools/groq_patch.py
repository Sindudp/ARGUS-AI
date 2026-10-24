

import litellm

_original_completion = litellm.completion


def _patched_completion(*args, **kwargs):
    messages = kwargs.get("messages")
    if messages:
        kwargs["messages"] = [
            {k: v for k, v in m.items() if k != "cache_breakpoint"}
            if isinstance(m, dict) else m
            for m in messages
        ]
    return _original_completion(*args, **kwargs)


litellm.completion = _patched_completion 
