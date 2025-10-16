from langchain.text_splitter import RecursiveCharacterTextSplitter

def get_text_splitter(chunk_size=2000, chunk_overlap=200, separators=None):
    """
    Retorna uma instância de RecursiveCharacterTextSplitter com parâmetros customizáveis.
    """
    if separators is None:
        separators = ["\n\n\n\n", "\n\n\n", "\n\n", "\n"]
    return RecursiveCharacterTextSplitter(
        separators=separators,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
    )
