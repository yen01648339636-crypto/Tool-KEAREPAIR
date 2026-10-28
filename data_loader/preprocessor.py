"""Code preprocessing utilities."""

import re
from typing import List, Optional
from loguru import logger


class CodePreprocessor:
    """Preprocessor for source code normalization and cleaning."""

    def __init__(self, remove_comments: bool = True, normalize_whitespace: bool = True):
        """
        Initialize code preprocessor.

        Args:
            remove_comments: Whether to remove code comments
            normalize_whitespace: Whether to normalize whitespace
        """
        self.remove_comments = remove_comments
        self.normalize_whitespace = normalize_whitespace

    def preprocess(self, code: str) -> str:
        """
        Preprocess source code.

        Args:
            code: Raw source code

        Returns:
            Preprocessed code
        """
        if not code:
            return ""

        processed = code

        if self.remove_comments:
            processed = self._remove_comments(processed)

        if self.normalize_whitespace:
            processed = self._normalize_whitespace(processed)

        return processed

    def _remove_comments(self, code: str) -> str:
        """
        Remove C/C++ style comments.

        Args:
            code: Source code with comments

        Returns:
            Code without comments
        """
        # Remove single-line comments (//)
        code = re.sub(r"//.*?$", "", code, flags=re.MULTILINE)
        
        # Remove multi-line comments (/* ... */)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        
        return code

    def _normalize_whitespace(self, code: str) -> str:
        """
        Normalize whitespace in code.

        Args:
            code: Source code with irregular whitespace

        Returns:
            Code with normalized whitespace
        """
        # Replace tabs with spaces
        code = code.replace("\t", "    ")
        
        # Remove trailing whitespace
        lines = [line.rstrip() for line in code.split("\n")]
        
        # Remove multiple consecutive blank lines
        cleaned_lines = []
        prev_blank = False
        for line in lines:
            is_blank = not line.strip()
            if is_blank and prev_blank:
                continue
            cleaned_lines.append(line)
            prev_blank = is_blank
        
        return "\n".join(cleaned_lines)

    def tokenize(self, code: str) -> List[str]:
        """
        Tokenize source code into tokens.

        Args:
            code: Source code

        Returns:
            List of tokens
        """
        # Simple tokenization by splitting on whitespace and operators
        # For production, use proper lexer (e.g., tree-sitter)
        tokens = re.findall(r'\w+|[^\w\s]', code)
        return tokens

    def extract_function(self, code: str, function_name: str) -> Optional[str]:
        """
        Extract a specific function from code.

        Args:
            code: Full source code
            function_name: Name of function to extract

        Returns:
            Function code if found, None otherwise
        """
        # Simple regex-based extraction (improve with AST parsing)
        pattern = rf'(\w+\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{[^}}]*\}})'
        match = re.search(pattern, code, re.DOTALL)
        
        if match:
            return match.group(1)
        
        logger.warning(f"Function '{function_name}' not found in code")
        return None
