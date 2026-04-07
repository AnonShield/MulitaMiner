import tiktoken
import subprocess
import sys
import warnings

def get_tokenizer(llm_config: dict = None):
    """
    Retorna um tokenizador adequado para o modelo, priorizando a configuração explícita.
    A função agora é mais robusta e garante o uso de cache para tokenizadores Hugging Face.
    """
    if llm_config:
        tokenizer_config = llm_config.get('tokenizer')
        if tokenizer_config and isinstance(tokenizer_config, dict):
            try:
                print(f"🔧 DEBUG: Attempting to load tokenizer with config: {tokenizer_config}")
                tokenizer = _load_tokenizer(tokenizer_config)
                print(f"✅ DEBUG: Successfully loaded tokenizer object: {type(tokenizer)}")
                return tokenizer
            except Exception as e:
                print(f"🛑 Failed to load tokenizer from config. Error: {e}. Falling back.")

    # Fallback universal para garantir que sempre haja um tokenizador.
    return tiktoken.get_encoding("cl100k_base")


def _load_tokenizer(tokenizer_config: dict):
    """Carrega um tokenizador com base na configuração fornecida."""
    tokenizer_type = tokenizer_config.get('type', 'tiktoken')
    model_name = tokenizer_config.get('model')

    if not model_name:
        raise ValueError("Tokenizer 'model' not specified in config.")

    if tokenizer_type == 'huggingface':
        try:
            from transformers import AutoTokenizer
        except ImportError:
            print("📦 Installing 'transformers' library for Hugging Face tokenizer...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "transformers"])
                from transformers import AutoTokenizer
                print("✅ 'transformers' installed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"🛑 Failed to install 'transformers'. Please install it manually: pip install transformers. Error: {e}")
                raise ImportError("transformers library is required but installation failed.")
        
        print(f"🔧 DEBUG: Loading Hugging Face tokenizer: {model_name}")
        # from_pretrained lida com o cache automaticamente.
        return AutoTokenizer.from_pretrained(model_name)
    
    elif tokenizer_type == 'tiktoken':
        print(f"🔧 DEBUG: Loading tiktoken with encoding: {model_name}")
        return tiktoken.get_encoding(model_name)
        
    else:
        raise ValueError(f"Unsupported tokenizer type: {tokenizer_type}")


def count_tokens(text: str, tokenizer=None) -> int:
    """
    Conta tokens de forma agnóstica ao tipo de tokenizador.
    """
    if tokenizer is None:
        warnings.warn(
            "count_tokens was called without a tokenizer. Falling back to default 'cl100k_base'.",
            RuntimeWarning
        )
        tokenizer = tiktoken.get_encoding("cl100k_base")
    
    return len(tokenizer.encode(text))

