"""
PDF processing module for PDF Vulnerability Extractor.

This module handles PDF loading, text extraction, chunking, and vector store creation.
"""

import os
import logging
from typing import List
from pathlib import Path

from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import CharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS


class PDFProcessor:
    """Handles PDF processing and vector store creation."""
    
    def __init__(self, chunk_size: int = 1000, chunk_overlap: int = 200):
        """Initialize PDF processor.
        
        Args:
            chunk_size: Size of text chunks
            chunk_overlap: Overlap between chunks
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
    
    def validate_pdf_path(self, pdf_path: str) -> None:
        """Validate that PDF file exists.
        
        Args:
            pdf_path: Path to PDF file
            
        Raises:
            FileNotFoundError: If PDF file doesn't exist
        """
        if not Path(pdf_path).exists():
            logging.error(f"PDF file '{pdf_path}' not found")
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
    
    def load_pdf_documents(self, pdf_path: str) -> List:
        """Load PDF documents using PyPDFLoader.
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            List of document objects
        """
        self.validate_pdf_path(pdf_path)
        
        # logging.info("Loading PDF document...")  # Commented to reduce log noise
        loader = PyPDFLoader(pdf_path)
        documents = loader.load()
        
        logging.info(f"Loaded PDF with {len(documents)} pages")
        return documents
    
    def split_documents(self, documents: List) -> List:
        """Split documents into text chunks.
        
        Args:
            documents: List of document objects
            
        Returns:
            List of text chunks
        """
        # logging.info("Splitting text into chunks...")  # Commented to reduce log noise
        text_splitter = CharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap
        )
        texts = text_splitter.split_documents(documents)
        
        logging.info(f"Created {len(texts)} text chunks for processing")
        return texts
    
    def load_and_process_pdf(self, pdf_path: str) -> List:
        """Complete PDF processing pipeline.
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            List of processed text chunks
        """
        documents = self.load_pdf_documents(pdf_path)
        texts = self.split_documents(documents)
        return texts
    
    def create_vector_store(self, texts: List):
        """Create FAISS vector store from text chunks.
        
        Args:
            texts: List of text chunks
            
        Returns:
            FAISS vector store
        """
        # logging.info("Creating embeddings and FAISS vector store...")  # Commented to reduce log noise
        embeddings = OpenAIEmbeddings()
        vector_store = FAISS.from_documents(texts, embeddings)
        logging.info("Vector store created successfully")
        return vector_store